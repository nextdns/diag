package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nextdns/diag/traceroute"
)

type Report struct {
	Contact string `json:",omitempty"`
	HasV6   bool
	Test    Test

	PrimaryTraceroute    []traceroute.Hop `json:",omitempty"`
	SecondaryTraceroute  []traceroute.Hop `json:",omitempty"`
	PrimaryTraceroute6   []traceroute.Hop `json:",omitempty"`
	SecondaryTraceroute6 []traceroute.Hop `json:",omitempty"`

	Primary    *Ping  `json:",omitempty"`
	Secondary  *Ping  `json:",omitempty"`
	Primary6   *Ping  `json:",omitempty"`
	Secondary6 *Ping  `json:",omitempty"`
	Top        []Ping `json:",omitempty"`
}

type Test struct {
	Status   string
	Protocol string `json:",omitempty"`
	Client   string `json:",omitempty"`
	Resolver string `json:",omitempty"`
	DestIP   string `json:",omitempty"`
	Server   string `json:",omitempty"`
}

func (p Test) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "status: %s\n", p.Status)
	fmt.Fprintf(&sb, "client: %s\n", p.Client)
	if p.Protocol != "" {
		fmt.Fprintf(&sb, "protocol: %s\n", p.Protocol)
		fmt.Fprintf(&sb, "dest IP: %s\n", p.DestIP)
		fmt.Fprintf(&sb, "server: %s", p.Server)
	} else {
		fmt.Fprintf(&sb, "resolver: %s", p.Resolver)
	}
	return sb.String()
}

type Ping struct {
	Pop      string `json:",omitempty"`
	Protocol int
	RTT      time.Duration
}

func (p Ping) String() string {
	if p.Protocol == 6 {
		return fmt.Sprintf("%s (IPv6): %s", p.Pop, p.RTT)
	}
	return fmt.Sprintf("%s: %s", p.Pop, p.RTT)
}

type RouterTarget struct {
	IPs []string
}

func main() {
	if runtime.GOOS == "windows" {
		fmt.Println("")
		fmt.Println("Welcome to NextDNS network diagnostic tool.")
		fmt.Println("")
		fmt.Println("This tool will capture latency and routing information regarding")
		fmt.Println("the connectivity of your network with NextDNS.")
		fmt.Println("")
		fmt.Println("The source code of this tool is available at https://github.com/nextdns/diag")
		fmt.Println("")
		fmt.Println("Do you want to continue? (press enter to accept)")
		fmt.Scanln()
	}

	var r Report
	r.HasV6 = hasIPv6()
	r.Test = test()
	r.PrimaryTraceroute = trace("primary IPv4", "45.90.28.0")
	r.SecondaryTraceroute = trace("secondary IPv4", "45.90.30.0")
	if r.HasV6 {
		r.PrimaryTraceroute6 = trace("primary IPv6", "2a07:a8c0::")
		r.SecondaryTraceroute6 = trace("secondary IPv6", "2a07:a8c1::")
	}
	r.Primary = pop("primary IPv4", "45.90.28.0")
	r.Secondary = pop("secondary IPv4", "45.90.30.0")
	if r.HasV6 {
		r.Primary6 = pop("primary IPv6", "2a07:a8c0::")
		r.Secondary6 = pop("secondary IPv6", "2a07:a8c1::")
	}
	r.Top = pings(r.HasV6)

	fmt.Print("Do you want to send this report? [Y/n]: ")
	var resp string
	fmt.Scanln(&resp)
	if resp != "" && resp[0] != 'y' && resp[0] != 'Y' {
		return
	}
	fmt.Print("Optional email in case we need additional info: ")
	fmt.Scanln(&r.Contact)

	b, err := json.Marshal(r)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Print("Posting...\r")
	req, _ := http.NewRequest("POST", "https://api.nextdns.io/diagnostic", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Post unsuccessful: %v\n", err)
		fmt.Println("Please report this issue on https://github.com/nextdns/diag")
		os.Exit(1)
	}
	if res.StatusCode != http.StatusOK {
		fmt.Printf("Post unsuccessful: status %d\n", res.StatusCode)
		_, _ = io.Copy(os.Stderr, res.Body)
		os.Exit(1)
	}
	result := struct {
		ID string
	}{}
	j := json.NewDecoder(res.Body)
	_ = j.Decode(&result)
	fmt.Printf("Posted: https://nextdns.io/diag/%s\n", result.ID)
	if runtime.GOOS == "windows" {
		fmt.Scanln()
	}
}

func hasIPv6() bool {
	fmt.Println("Testing IPv6 connectivity")
	c, err := net.Dial("tcp", "[2a00:1450:4007:80a::2013]:80")
	if c != nil {
		c.Close()
	}
	v6 := err == nil
	fmt.Printf(indent("available: %v\n"), v6)
	return v6
}

func trace(name string, dest string) []traceroute.Hop {
	fmt.Printf("Traceroute for %s (%s)\n", name, dest)
	var t traceroute.Tracer
	c := make(chan traceroute.Hop)
	var hops []traceroute.Hop
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for hop := range c {
			hops = append(hops, hop)
			fmt.Println(indent(hop.String()))
		}
	}()
	err := t.Trace(context.Background(), net.ParseIP(dest), c)
	if err != nil {
		fmt.Printf(indent("error: %v\n"), err)
	}
	close(c)
	wg.Wait()
	return hops
}

func test() Test {
	fmt.Println("Fetching https://test.nextdns.io")
	req, _ := http.NewRequest("GET", "https://test.nextdns.io", nil)
	req.Header.Set("User-Agent", "curl")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf(indent("Fetch error: %v\n"), err)
		return Test{}
	}
	defer res.Body.Close()
	var t Test
	j := json.NewDecoder(res.Body)
	if err := j.Decode(&t); err != nil {
		fmt.Printf(indent("Cannot decode response: %v\n"), err)
	}
	fmt.Println(indent(t.String()))
	return t
}

func pop(name, ip string) *Ping {
	fmt.Printf("Fetching PoP name for %s (%s)\n", name, ip)
	req, _ := http.NewRequest("GET", "https://dns.nextdns.io/info", nil)
	cl := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
			},
		},
	}
	res, err := cl.Do(req)
	if err != nil {
		fmt.Printf("Fetch error: %v\n", err)
		return nil
	}
	defer res.Body.Close()
	var p Ping
	j := json.NewDecoder(res.Body)
	if err := j.Decode(&p); err != nil {
		fmt.Printf(indent("Cannot decode response: %v\n"), err)
	}
	p.RTT *= 100
	fmt.Println(indent(p.String()))
	return &p
}

func pings(v6 bool) []Ping {
	fmt.Println("Pinging PoPs")
	res, err := http.Get("https://router.nextdns.io/?limit=10&stack=dual")
	if err != nil {
		fmt.Printf(indent("error: %v\n"), err)
		return nil
	}
	defer res.Body.Close()
	var targets []RouterTarget
	j := json.NewDecoder(res.Body)
	if err := j.Decode(&targets); err != nil {
		fmt.Printf(indent("Cannot decode response: %v\n"), err)
		return nil
	}
	c := make(chan Ping)
	var total int
	for _, t := range targets {
		for _, ip := range t.IPs {
			if !v6 && strings.IndexByte(ip, ':') != -1 {
				continue
			}
			total++
			go func(ip string) {
				c <- ping(ip)
			}(ip)
		}
	}
	var ps []Ping
	for ; total > 0; total-- {
		if p := <-c; p.Pop != "" {
			fmt.Println(indent(p.String()))
			ps = append(ps, p)
		}
	}
	return ps
}

func ping(ip string) (p Ping) {
	p.Protocol = 4
	if net.ParseIP(ip).To4() == nil {
		p.Protocol = 6
	}
	res, err := http.Get("http://" + net.JoinHostPort(ip, "80") + "/info")
	if err != nil {
		return p
	}
	defer res.Body.Close()
	j := json.NewDecoder(res.Body)
	_ = j.Decode(&p)
	p.RTT *= 100
	return p

}

func indent(s string) string {
	return "  " + strings.TrimRight(strings.ReplaceAll(s, "\n", "\n  "), " ")
}
