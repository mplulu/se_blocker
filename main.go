package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
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
}

type Center struct {
	env            *ENV
	tlgBot         *rano.Rano
	blockedIpList  []*BlockedIP
	lastTotalCount int

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
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		`sudo firewall-cmd --timeout=%v --add-rich-rule="rule family='ipv4' source address='%v' drop"`,
		center.env.BanDuration, ipObjc.ip))
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output1 %v %v", string(stdout), err)
		return
	}
	ipObjc.blockedAt = time.Now()
	center.blockedIpList = append(center.blockedIpList, ipObjc)
	log.Log("block %v(%v)", ipObjc.ip, ipObjc.count)
}

func (center *Center) IsIpAlreadyBlocked(ip string) bool {
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

func (center *Center) scheduleBlocker() {
	env := center.env
	cmd := exec.Command("sh", "-c", "netstat -tn 2>/dev/null | grep :443 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr")
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
			finished := make(chan bool, 1)
			counter := 0
			log.Log("will block %v ips", len(willBeBlockedList))
			message := fmt.Sprintf("%v will block %v ips (totalConnection %v=>%v, totalIps %v, average %.2f, TotalConnWillBeBlocked %v) (blocked last %v: %v). %v",
				center.env.OwnIp, len(willBeBlockedList),
				center.lastTotalCount, totalCount, totalIpAccess, float64(totalCount)/float64(totalIpAccess), totalCountWillBeBlocked,
				kExpireIpBlockedDuration.String(), len(center.blockedIpList), convertBlockedIPListToString(willBeBlockedList))
			center.notifyMT(message)
			for _, ip := range willBeBlockedList {
				queues <- true
				go func(ipInBlock *BlockedIP) {
					center.blockIPInFirewall(ipInBlock)
					counter++
					if counter == len(willBeBlockedList) {
						finished <- true
					}
					<-queues
				}(ip)
			}
			<-finished
		}
	}

	filterExpiredBlockIpList := []*BlockedIP{}
	for _, blockedIp := range center.blockedIpList {
		if time.Since(blockedIp.blockedAt) <= kExpireIpBlockedDuration {
			filterExpiredBlockIpList = append(filterExpiredBlockIpList, blockedIp)
		}
	}
	center.blockedIpList = filterExpiredBlockIpList
	center.lastTotalCount = totalCount
	<-time.After(kInterval)
	go center.scheduleBlocker()
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
	go center.scheduleBlocker()
	select {}
}
