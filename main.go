package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/domainr/whois"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "timeout")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments] <domain list>\n\nAvailable arguments:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()
	query := flag.Arg(0)

	if query == "" {
		flag.Usage()
	}

	domains := strings.Split(query, ",")

	for _, domain := range domains {
		c := whois.NewClient(0)
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		req, err := whois.NewRequest(domain)
		FatalIf(err)

		var res *whois.Response
		res, err = c.FetchContext(ctx, req)
		FatalIf(err)

		// Registry Expiry Date: 2020-07-16T08:02:15Z
		r, error := regexp.Compile("Registry Expiry Date: (?P<year>\\d+)-(?P<month>\\d+)-(?P<day>\\d+)T(?P<hour>\\d+):(?P<minute>\\d+):(?P<second>\\d+)Z")
		if error != nil {
			fmt.Println(error)
			continue
		}
		found := r.FindStringSubmatch(res.String())
		names := r.SubexpNames()
		groups := mapSubexpNames(found, names)
		expired := time.Date(groups["year"], time.Month(groups["month"]), groups["day"], groups["hour"], groups["minute"], groups["second"], 0, time.UTC)
		left := expired.Sub(time.Now())
		left_days := int(left.Hours() / 24)
		notify_days := []int{1, 2, 3, 4, 5, 6, 7, 345}
		notify := false
		for i := range notify_days {
			if notify_days[i] == left_days {
				notify = true
				break
			}
		}
		if notify {
			fmt.Printf("%s will expired after %d days -> %s.\n", domain, left_days, found[0])
			wechat_notify(domain, left_days, found[0])
		}
	}
}

func wechat_notify(domain string, left_days int, expire_date string) {
	url := os.Getenv("WECHAT_BOT")
	// fmt.Println(url)
	if url != "" {
		requestBody, err := json.Marshal(map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"content": fmt.Sprintf("%s <font color=\"warning\">%d</font>天后过期：\n>%s\n", domain, left_days, expire_date),
			},
		})
		if err != nil {
			//
		}

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
		if err != nil {
			//
		}
		defer resp.Body.Close()

		// body, err := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	//
		// }
		// fmt.Println(string(body))
	}
}

func mapSubexpNames(m, n []string) map[string]int {
	m, n = m[1:], n[1:]
	r := make(map[string]int, len(m))
	for i, _ := range n {
		number, _ := strconv.Atoi(m[i])
		r[n[i]] = number
	}
	return r
}

func FatalIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(-1)
}
