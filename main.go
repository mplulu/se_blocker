package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os/exec"
	"strconv"
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
	// Use fmt.Sprintf to insert the port dynamically
	cmdStr := fmt.Sprintf("netstat -tn 2>/dev/null | grep :%d | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr", targetPort)
	cmd := exec.Command("sh", "-c", cmdStr)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output0 %v %v", string(stdout), err)
	}
	lines := strings.Split(string(stdout), "\n")

	totalCount := 0
	totalIpAccess := 0
	totalCountWillBeBlocked := 0

	willBeBlockedList := []*BlockedIP{}

	for _, blockedIP := range center.potentialBlockedList {
		blockedIP.isConsecutive = false
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		tokens := strings.Split(line, " ")
		if len(tokens) == 2 {
			countStr := strings.TrimSpace(tokens[0])
			ip := strings.TrimSpace(tokens[1])
			count, _ := strconv.Atoi(countStr)
			totalCount += count
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
			totalIpAccess++
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
