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
const kMaxCount = 50

type ENV struct {
	WhitelistIps []string `yaml:"whitelist_ips"`
}

func blockIPInFirewall(ip string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf(`sudo firewall-cmd --timeout=30m --add-rich-rule="rule family='ipv4' source address='%v' reject"`, ip))
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output1 %v %v", string(stdout), err)
		return
	}
	log.Log("block %v", ip)
}

func scheduleBlocker(env *ENV) {
	cmd := exec.Command("sh", "-c", "netstat -tn 2>/dev/null | grep :443 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr")
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.LogSerious("output0 %v %v", string(stdout), err)
	}
	lines := strings.Split(string(stdout), "\n")
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
			if count > kMaxCount && !utils.ContainsByString(env.WhitelistIps, ip) {
				blockIPInFirewall(ip)
			}
		}
	}
	<-time.After(kInterval)
	go scheduleBlocker(env)
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UTC().UnixNano())
	var env *ENV
	renv.ParseCmd(&env)
	log.Log("Whitelist IPs: %v", strings.Join(env.WhitelistIps, " "))
	go scheduleBlocker(env)
	select {}
}
