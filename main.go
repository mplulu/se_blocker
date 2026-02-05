package main

import (
	"flag"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mplulu/log"
	"github.com/mplulu/rano"
	"github.com/mplulu/renv"
)

const kInterval = 1 * time.Second

// cache TTL to avoid re-blocking IPs that appear in ss due to lingering connections (actual ban is BanDuration in ipset)
const kRecentlyBlockedCacheTTL = 10 * time.Minute
const kIpsetNameV4 = "se_blocked_v4"
const kIpsetNameV6 = "se_blocked_v6"

type ENV struct {
	WhitelistIps     []string `yaml:"whitelist_ips"`
	OwnIp            string   `yaml:"own_ip"`
	TelegramBotToken string   `yaml:"telegram_bot_token"`
	TelegramChatId   string   `yaml:"telegram_chat_id"`

	MaxCount      int    `yaml:"max_count"`
	MaxTotalCount int    `yaml:"max_total_count"`
	BanDuration   string `yaml:"ban_duration"`

	MaxCountForStrike int `yaml:"max_count_for_strike"`
	StrikeCount       int `yaml:"strike_count"`
	TargetPort        int `yaml:"target_port"`
}

type Center struct {
	env                  *ENV
	tlgBot               *rano.Rano
	recentlyBlockedCache map[string]*BlockedIP
	recentlyBlockedMu    sync.RWMutex
	lastTotalCount       int

	potentialBlockedMap map[string]*PotentialBlockedIP
	potentialBlockedMu  sync.Mutex

	whitelistMap map[string]bool
	ipsetReady   bool
}

type BlockedIP struct {
	ip        string
	blockedAt time.Time
	count     int

	isStrike bool
}

type PotentialBlockedIP struct {
	ip            string
	count         int
	strikeCount   int
	isConsecutive bool
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

func (center *Center) isWhitelisted(ip string) bool {
	return center.whitelistMap[ip]
}

func (center *Center) initIpset() error {
	createV4 := exec.Command("sudo", "ipset", "create", kIpsetNameV4, "hash:ip", "timeout", "0", "-exist")
	if output, err := createV4.CombinedOutput(); err != nil {
		log.LogSerious("failed to create ipset v4: %v %v", string(output), err)
		return err
	}

	createV6 := exec.Command("sudo", "ipset", "create", kIpsetNameV6, "hash:ip", "family", "inet6", "timeout", "0", "-exist")
	if output, err := createV6.CombinedOutput(); err != nil {
		log.LogSerious("failed to create ipset v6: %v %v", string(output), err)
		return err
	}

	ruleV4 := exec.Command("sudo", "firewall-cmd",
		"--permanent",
		fmt.Sprintf("--add-rich-rule=rule family='ipv4' source ipset='%s' drop", kIpsetNameV4))
	if output, err := ruleV4.CombinedOutput(); err != nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "ALREADY_ENABLED") {
			log.LogSerious("failed to add firewall rule v4: %v %v", outputStr, err)
		}
	}

	ruleV6 := exec.Command("sudo", "firewall-cmd",
		"--permanent",
		fmt.Sprintf("--add-rich-rule=rule family='ipv6' source ipset='%s' drop", kIpsetNameV6))
	if output, err := ruleV6.CombinedOutput(); err != nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "ALREADY_ENABLED") {
			log.LogSerious("failed to add firewall rule v6: %v %v", outputStr, err)
		}
	}

	reload := exec.Command("sudo", "firewall-cmd", "--reload")
	if output, err := reload.CombinedOutput(); err != nil {
		log.LogSerious("failed to reload firewall: %v %v", string(output), err)
		return err
	}

	log.Log("ipset initialized: %s (IPv4), %s (IPv6)", kIpsetNameV4, kIpsetNameV6)
	return nil
}

func convertBlockedIPListToString(list []*BlockedIP) string {
	tokens := []string{}
	for _, entry := range list {
		if entry.isStrike {
			token := fmt.Sprintf("%v(%v)[strike]", entry.ip, entry.count)
			tokens = append(tokens, token)
		} else {
			token := fmt.Sprintf("%v(%v)", entry.ip, entry.count)
			tokens = append(tokens, token)
		}
	}
	return strings.Join(tokens, " ")
}

func (center *Center) blockIPInFirewall(ipObjc *BlockedIP) {
	if !isValidIP(ipObjc.ip) {
		log.LogSerious("invalid IP format: %v", ipObjc.ip)
		return
	}

	var cmd *exec.Cmd
	if center.ipsetReady {
		ipsetName := kIpsetNameV4
		if isIPv6(ipObjc.ip) {
			ipsetName = kIpsetNameV6
		}
		timeoutSecs := center.getBanDurationSeconds()
		cmd = exec.Command("sudo", "ipset", "add", ipsetName, ipObjc.ip, "timeout", fmt.Sprintf("%d", timeoutSecs), "-exist")
	} else {
		family := "ipv4"
		if isIPv6(ipObjc.ip) {
			family = "ipv6"
		}
		args := []string{
			"firewall-cmd",
			fmt.Sprintf("--timeout=%v", center.env.BanDuration),
			fmt.Sprintf("--add-rich-rule=rule family='%s' source address='%v' drop", family, ipObjc.ip),
		}
		cmd = exec.Command("sudo", args...)
	}

	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("block failed %v %v", string(stdout), err)
		return
	}

	center.recentlyBlockedMu.Lock()
	defer center.recentlyBlockedMu.Unlock()

	ipObjc.blockedAt = time.Now()
	center.recentlyBlockedCache[ipObjc.ip] = ipObjc
	log.Log("block %v(%v) ipv6=%v", ipObjc.ip, ipObjc.count, isIPv6(ipObjc.ip))
}

func (center *Center) getBanDurationSeconds() int64 {
	duration, err := time.ParseDuration(center.env.BanDuration)
	if err != nil {
		return 3600
	}
	return int64(duration.Seconds())
}

func (center *Center) isRecentlyBlocked(ip string) bool {
	center.recentlyBlockedMu.RLock()
	defer center.recentlyBlockedMu.RUnlock()
	_, exists := center.recentlyBlockedCache[ip]
	return exists
}

func (center *Center) notifyMT(text string) {
	if center.tlgBot != nil {
		center.tlgBot.Send(text)
	}
}

func (center *Center) runBlocker() {
	env := center.env
	targetPort := 443
	if env.TargetPort > 0 {
		targetPort = env.TargetPort
	}

	cmd := exec.Command("ss", "-ntH", fmt.Sprintf("sport = :%d", targetPort))
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("ss command failed: %v output: %v", err, string(stdout))
		return
	}

	lines := strings.Split(string(stdout), "\n")

	totalCount := 0
	totalIpAccess := 0
	totalCountWillBeBlocked := 0

	// Use a map for counting to avoid 'sort | uniq -c' shell overhead
	ipCounts := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// ss -ntH output format: State Recv-Q Send-Q Local_Address:Port Peer_Address:Port
		// Example: ESTAB 0 0 10.0.0.1:443 1.2.3.4:5678
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		remoteAddr := fields[4]
		if !strings.Contains(remoteAddr, ":") {
			continue
		}

		lastColon := strings.LastIndex(remoteAddr, ":")
		if lastColon == -1 {
			continue
		}
		ip := remoteAddr[:lastColon]
		ip = strings.TrimPrefix(ip, "[")
		ip = strings.TrimSuffix(ip, "]")

		if ip == "" || ip == "*" || !isValidIP(ip) {
			continue
		}

		ipCounts[ip]++
	}

	willBeBlockedList := []*BlockedIP{}

	center.potentialBlockedMu.Lock()
	for _, blockedIP := range center.potentialBlockedMap {
		blockedIP.isConsecutive = false
	}

	for ip, count := range ipCounts {
		totalCount += count
		totalIpAccess++

		if !center.isWhitelisted(ip) && !center.isRecentlyBlocked(ip) {
			if count > center.env.MaxCount {
				willBeBlockedList = append(willBeBlockedList, &BlockedIP{
					ip:    ip,
					count: count,
				})
				totalCountWillBeBlocked += count
			} else if center.env.MaxCountForStrike > 0 && count > center.env.MaxCountForStrike {
				if center.potentialBlockedMap[ip] == nil {
					center.potentialBlockedMap[ip] = &PotentialBlockedIP{
						ip:            ip,
						count:         count,
						strikeCount:   1,
						isConsecutive: true,
					}
				} else {
					potentialBlockedIP := center.potentialBlockedMap[ip]
					potentialBlockedIP.strikeCount += 1
					potentialBlockedIP.count = count
					potentialBlockedIP.isConsecutive = true
				}
			}
		}
	}

	for ip, blockedIP := range center.potentialBlockedMap {
		if !blockedIP.isConsecutive {
			delete(center.potentialBlockedMap, ip)
			continue
		}
		if blockedIP.strikeCount >= center.env.StrikeCount {
			willBeBlockedList = append(willBeBlockedList, &BlockedIP{
				ip:       ip,
				count:    blockedIP.count,
				isStrike: true,
			})
			totalCountWillBeBlocked += blockedIP.count
			delete(center.potentialBlockedMap, ip)
		}
	}
	center.potentialBlockedMu.Unlock()
	if totalCount > center.env.MaxTotalCount {
		avgPerIp := float64(0)
		if totalIpAccess > 0 {
			avgPerIp = float64(totalCount) / float64(totalIpAccess)
		}
		avgWillBeBlocked := float64(0)
		if len(willBeBlockedList) > 0 {
			avgWillBeBlocked = float64(totalCountWillBeBlocked) / float64(len(willBeBlockedList))
		}

		log.Log("Stats totalConnection %v, totalIps %v, average %.2f. TotalConnWillBeBlocked %v, totalIpsWillBeBlocked %v, average %.2f ",
			totalCount, totalIpAccess, avgPerIp,
			totalCountWillBeBlocked, len(willBeBlockedList), avgWillBeBlocked)

		if len(willBeBlockedList) > 0 {
			queues := make(chan bool, 30)
			var wg sync.WaitGroup

			log.Log("will block %v ips", len(willBeBlockedList))

			center.recentlyBlockedMu.RLock()
			recentlyBlockedCount := len(center.recentlyBlockedCache)
			center.recentlyBlockedMu.RUnlock()

			message := fmt.Sprintf("%v will block %v ips (totalConnection %v=>%v, totalIps %v, average %.2f, TotalConnWillBeBlocked %v) (blocked last %v: %v). %v",
				center.env.OwnIp, len(willBeBlockedList),
				center.lastTotalCount, totalCount, totalIpAccess, avgPerIp, totalCountWillBeBlocked,
				kRecentlyBlockedCacheTTL.String(), recentlyBlockedCount, convertBlockedIPListToString(willBeBlockedList))
			center.notifyMT(message)
			for _, ip := range willBeBlockedList {
				queues <- true
				wg.Add(1)
				go func(ipInBlock *BlockedIP) {
					defer wg.Done()
					center.blockIPInFirewall(ipInBlock)
					<-queues
				}(ip)
			}
			wg.Wait()
		}
	}

	center.recentlyBlockedMu.Lock()
	for ip, blockedIp := range center.recentlyBlockedCache {
		if time.Since(blockedIp.blockedAt) > kRecentlyBlockedCacheTTL {
			delete(center.recentlyBlockedCache, ip)
		}
	}
	center.recentlyBlockedMu.Unlock()

	center.lastTotalCount = totalCount
}

func (center *Center) Start() {
	for {
		center.runBlocker()
		time.Sleep(kInterval)
	}
}

func main() {
	flag.Parse()
	var env *ENV
	renv.ParseCmd(&env)
	log.Log("Whitelist IPs: %v", strings.Join(env.WhitelistIps, " "))

	whitelistMap := make(map[string]bool)
	for _, ip := range env.WhitelistIps {
		whitelistMap[ip] = true
	}

	center := &Center{
		env:                  env,
		recentlyBlockedCache: make(map[string]*BlockedIP),
		potentialBlockedMap:  make(map[string]*PotentialBlockedIP),
		whitelistMap:         whitelistMap,
	}

	if err := center.initIpset(); err != nil {
		log.Log("ipset init failed, falling back to individual firewall rules: %v", err)
		center.ipsetReady = false
	} else {
		center.ipsetReady = true
	}

	if env.TelegramBotToken != "" && env.TelegramChatId != "" {
		center.tlgBot = rano.NewRano(env.TelegramBotToken, []string{env.TelegramChatId})
	}
	go center.Start()
	select {}
}
