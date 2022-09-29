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
const kMaxCount = 50
const kMaxTotalCount = 10000
const kExpireIpBlockedDuration = 5 * time.Second

type ENV struct {
	WhitelistIps     []string `yaml:"whitelist_ips"`
	OwnIp            string   `yaml:"own_ip"`
	TelegramBotToken string   `yaml:"telegram_bot_token"`
	TelegramChatId   string   `yaml:"telegram_chat_id"`

	MaxCount      int    `yaml:"max_count"`
	MaxTotalCount int    `yaml:"max_total_count"`
	BanDuration   string `yaml:"ban_duration"`
}

type Center struct {
	env           *ENV
	tlgBot        *rano.Rano
	blockedIpList []*BlockedIP
}

type BlockedIP struct {
	ip        string
	blockedAt time.Time
}

func (center *Center) blockIPInFirewall(ip string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		`sudo firewall-cmd --timeout=%v --add-rich-rule="rule family='ipv4' source address='%v' drop"`,
		center.env.BanDuration, ip))
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output1 %v %v", string(stdout), err)
		return
	}
	center.blockedIpList = append(center.blockedIpList, &BlockedIP{
		ip:        ip,
		blockedAt: time.Now(),
	})
	log.Log("block %v", ip)
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

	willBeBlockedList := []string{}

	totalCount := 0
	totalIpAccess := 0
	totalCountWillBeBlocked := 0
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
			if count > center.env.MaxCount && !utils.ContainsByString(env.WhitelistIps, ip) && !center.IsIpAlreadyBlocked(ip) {
				willBeBlockedList = append(willBeBlockedList, ip)
				totalCountWillBeBlocked += count
			}
			totalIpAccess++
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
			message := fmt.Sprintf("%v will block %v ips (blocked last %v: %v). %v", center.env.OwnIp, len(willBeBlockedList),
				kExpireIpBlockedDuration.String(), len(center.blockedIpList), strings.Join(willBeBlockedList, " "))
			center.notifyMT(message)
			for _, ip := range willBeBlockedList {
				queues <- true
				go func(ipInBlock string) {
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
		env:           env,
		blockedIpList: []*BlockedIP{},
	}
	if env.TelegramBotToken != "" && env.TelegramChatId != "" {
		center.tlgBot = rano.NewRano(env.TelegramBotToken, []string{env.TelegramChatId})
	}
	go center.scheduleBlocker()
	select {}
}
