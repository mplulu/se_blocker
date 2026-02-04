package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mplulu/rano"

	"github.com/mplulu/renv"

	"github.com/mplulu/utils"

	"github.com/mplulu/log"
)

const kInterval = 1 * time.Second
const kExpireIpBlockedDuration = 10 * time.Minute

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
	env             *ENV
	tlgBot          *rano.Rano
	blockedIpList   []*BlockedIP
	blockedIpListMu sync.Mutex
	lastTotalCount  int

	potentialBlockedList map[string]*PotentialBlockedIP
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
	// Use direct command execution to avoid shell injection and improve safety
	// Note: We use "sudo" directly. Ensure the user running this binary has sudo access without password or is root.
	args := []string{
		"firewall-cmd",
		fmt.Sprintf("--timeout=%v", center.env.BanDuration),
		fmt.Sprintf("--add-rich-rule=rule family='ipv4' source address='%v' drop", ipObjc.ip),
	}
	cmd := exec.Command("sudo", args...)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output1 %v %v", string(stdout), err)
		return
	}

	center.blockedIpListMu.Lock()
	defer center.blockedIpListMu.Unlock()

	ipObjc.blockedAt = time.Now()
	center.blockedIpList = append(center.blockedIpList, ipObjc)
	log.Log("block %v(%v)", ipObjc.ip, ipObjc.count)
}

func (center *Center) IsIpAlreadyBlocked(ip string) bool {
	center.blockedIpListMu.Lock()
	defer center.blockedIpListMu.Unlock()
	for _, blockedIP := range center.blockedIpList {
		if blockedIP.ip == ip {
			return true
		}
	}
	return false
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

	// Optimization: Use 'ss' instead of 'netstat'. It is much faster (reads from netlink).
	// We use -n (numeric), -t (tcp), -H (no header).
	// We assume Linux environment where ss is available.
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

		// Parse IP from line.
		// ss output format: State Recv-Q Send-Q Local_Address:Port Peer_Address:Port

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		var remoteAddr string

		// In ss -ntH: State is usually first.
		// ESTAB      0      0              10.0.0.1:443              1.2.3.4:5678
		// The peer address is usually the last field.

		if strings.Contains(strings.ToLower(line), "estab") || strings.Contains(strings.ToLower(line), "syn-recv") || strings.Contains(strings.ToLower(line), "time-wait") || (len(fields) >= 4 && strings.Contains(fields[0], "ESTAB")) {
			// ss output usually puts peer address at the last or second to last index
			// Let's grab the last field that looks like an IP:Port
			remoteAddr = fields[len(fields)-1]
			// For ss -ntH: State, Recv-Q, Send-Q, Local, Peer
			// Ensure we aren't picking up something else if format is slightly different,
			// but usually last field is safe for -ntH
			if len(fields) >= 5 {
				remoteAddr = fields[4]
			}
		} else {
			// If it doesn't match expected states but has enough fields, try 5th column (standard ss output location for peer)
			if len(fields) >= 5 {
				remoteAddr = fields[4]
			}
		}

		// Clean up the IP (remove port)
		if strings.Contains(remoteAddr, ":") {
			// Handle IPv6 if needed, but assuming IPv4 based on original code 'cut -d: -f1'
			// If it's 1.2.3.4:5678, LastIndex is safer.
			lastColon := strings.LastIndex(remoteAddr, ":")
			if lastColon != -1 {
				remoteAddr = remoteAddr[:lastColon]
			}
		} else {
			// If no colon, might be just IP or invalid
			continue
		}

		// Skip empty or malformed IPs
		if remoteAddr == "" || remoteAddr == "*" {
			continue
		}

		ipCounts[remoteAddr]++
	}

	willBeBlockedList := []*BlockedIP{}

	for _, blockedIP := range center.potentialBlockedList {
		blockedIP.isConsecutive = false
	}

	// Process counts
	for ip, count := range ipCounts {
		totalCount += count
		totalIpAccess++ // Distinct IPs

		if !utils.ContainsByString(env.WhitelistIps, ip) && !center.IsIpAlreadyBlocked(ip) {
			if count > center.env.MaxCount {
				willBeBlockedList = append(willBeBlockedList, &BlockedIP{
					ip:    ip,
					count: count,
				})
				totalCountWillBeBlocked += count
			} else if center.env.MaxCountForStrike > 0 && count > center.env.MaxCountForStrike {
				if center.potentialBlockedList[ip] == nil {
					center.potentialBlockedList[ip] = &PotentialBlockedIP{
						ip:            ip,
						count:         count,
						strikeCount:   1,
						isConsecutive: true,
					}
				} else {
					potentialBlockedIP := center.potentialBlockedList[ip]
					potentialBlockedIP.strikeCount += 1
					potentialBlockedIP.count = count
					potentialBlockedIP.isConsecutive = true
				}
			}
		}
	}

	for ip, blockedIP := range center.potentialBlockedList {
		if !blockedIP.isConsecutive {
			delete(center.potentialBlockedList, ip)
			continue
		}
		if blockedIP.strikeCount >= center.env.StrikeCount {
			willBeBlockedList = append(willBeBlockedList, &BlockedIP{
				ip:       ip,
				count:    blockedIP.count,
				isStrike: true,
			})
			totalCountWillBeBlocked += blockedIP.count
			delete(center.potentialBlockedList, ip)
		}
	}
	if totalCount > center.env.MaxTotalCount {
		log.Log("Stats totalConnection %v, totalIps %v, average %.2f. TotalConnWillBeBlocked %v, totalIpsWillBeBlocked %v, average %.2f ",
			totalCount, totalIpAccess, float64(totalCount)/float64(totalIpAccess),
			totalCountWillBeBlocked, len(willBeBlockedList), float64(totalCountWillBeBlocked)/float64(len(willBeBlockedList)))
		if len(willBeBlockedList) > 0 {
			queues := make(chan bool, 30)
			var wg sync.WaitGroup

			log.Log("will block %v ips", len(willBeBlockedList))

			center.blockedIpListMu.Lock()
			currentBlockedCount := len(center.blockedIpList)
			center.blockedIpListMu.Unlock()

			message := fmt.Sprintf("%v will block %v ips (totalConnection %v=>%v, totalIps %v, average %.2f, TotalConnWillBeBlocked %v) (blocked last %v: %v). %v",
				center.env.OwnIp, len(willBeBlockedList),
				center.lastTotalCount, totalCount, totalIpAccess, float64(totalCount)/float64(totalIpAccess), totalCountWillBeBlocked,
				kExpireIpBlockedDuration.String(), currentBlockedCount, convertBlockedIPListToString(willBeBlockedList))
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

	filterExpiredBlockIpList := []*BlockedIP{}
	center.blockedIpListMu.Lock()
	for _, blockedIp := range center.blockedIpList {
		if time.Since(blockedIp.blockedAt) <= kExpireIpBlockedDuration {
			filterExpiredBlockIpList = append(filterExpiredBlockIpList, blockedIp)
		}
	}
	center.blockedIpList = filterExpiredBlockIpList
	center.blockedIpListMu.Unlock()

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
	rand.Seed(time.Now().UTC().UnixNano())
	var env *ENV
	renv.ParseCmd(&env)
	log.Log("Whitelist IPs: %v", strings.Join(env.WhitelistIps, " "))
	center := &Center{
		env:                  env,
		blockedIpList:        []*BlockedIP{},
		potentialBlockedList: make(map[string]*PotentialBlockedIP),
	}
	if env.TelegramBotToken != "" && env.TelegramChatId != "" {
		center.tlgBot = rano.NewRano(env.TelegramBotToken, []string{env.TelegramChatId})
	}
	go center.Start()
	select {}
}
