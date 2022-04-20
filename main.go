package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mplulu/renv"

	"github.com/mplulu/utils"

	"github.com/mplulu/log"
)

const kInterval = 1 * time.Second
const kMaxCount = 30
const kBanForDurationStr = "30m"
const kCheckDuplicateBlockDuration = 5 * time.Minute

type ENV struct {
	WhitelistIps []string `yaml:"whitelist_ips"`
}

type Center struct {
	env           *ENV
	blockedIpList []*BlockedIP
}

type BlockedIP struct {
	ip        string
	blockedAt time.Time
}

func (center *Center) killTCPConnection(ip string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf(`sudo tcpkill -i any -9 host %v`, ip))
	_, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output3 %v", err)
		return
	}
}

func (center *Center) blockIPInFirewall(ip string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf(`sudo firewall-cmd --timeout=30m --add-rich-rule="rule family='ipv4' source address='%v' reject"`, ip))
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output1 %v %v", string(stdout), err)
		return
	}
	center.blockedIpList = append(center.blockedIpList, &BlockedIP{
		ip:        ip,
		blockedAt: time.Now(),
	})
	go center.killTCPConnection(ip)
	log.Log("block %v", ip)
}

func (center *Center) IsIpAlreadyBlocked(ip string) bool {
	for _, blockedIP := range center.blockedIpList {
		if blockedIP.ip == ip {
			return time.Since(blockedIP.blockedAt) < kCheckDuplicateBlockDuration
		}
	}
	return false
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
			if count > kMaxCount && !utils.ContainsByString(env.WhitelistIps, ip) && !center.IsIpAlreadyBlocked(ip) {
				willBeBlockedList = append(willBeBlockedList, ip)

			}
		}
	}

	if len(willBeBlockedList) > 0 {
		queues := make(chan bool, 30)
		finished := make(chan bool, 1)
		counter := 0
		log.Log("will block %v ips", len(willBeBlockedList))
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
	go center.scheduleBlocker()
	select {}
}
