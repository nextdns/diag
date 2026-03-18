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

	"github.com/nextdns/diag/traceback"
	"github.com/nextdns/diag/traceroute"
	"github.com/nextdns/nextdns/host"
)

type Report struct {
	Contact   string `json:",omitempty"`
	HasV6     bool
	Resolvers []string
	Test      Test

	ULLPrimary    *Ping  `json:",omitempty"`
	ULLSecondary  *Ping  `json:",omitempty"`
	ULLPrimary6   *Ping  `json:",omitempty"`
	ULLSecondary6 *Ping  `json:",omitempty"`
	Primary       *Ping  `json:",omitempty"`
	Secondary     *Ping  `json:",omitempty"`
	Primary6      *Ping  `json:",omitempty"`
	Secondary6    *Ping  `json:",omitempty"`
	Top           []Ping `json:",omitempty"`

	ULLPrimaryTraceroute    []traceroute.Hop `json:",omitempty"`
	ULLSecondaryTraceroute  []traceroute.Hop `json:",omitempty"`
	ULLPrimaryTraceroute6   []traceroute.Hop `json:",omitempty"`
	ULLSecondaryTraceroute6 []traceroute.Hop `json:",omitempty"`
	PrimaryTraceroute       []traceroute.Hop `json:",omitempty"`
	SecondaryTraceroute     []traceroute.Hop `json:",omitempty"`
	PrimaryTraceroute6      []traceroute.Hop `json:",omitempty"`
	SecondaryTraceroute6    []traceroute.Hop `json:",omitempty"`

	ULLPrimaryTraceback    []traceroute.Hop `json:",omitempty"`
	ULLSecondaryTraceback  []traceroute.Hop `json:",omitempty"`
	ULLPrimaryTraceback6   []traceroute.Hop `json:",omitempty"`
	ULLSecondaryTraceback6 []traceroute.Hop `json:",omitempty"`
	PrimaryTraceback       []traceroute.Hop `json:",omitempty"`
	SecondaryTraceback     []traceroute.Hop `json:",omitempty"`
	PrimaryTraceback6      []traceroute.Hop `json:",omitempty"`
	SecondaryTraceback6    []traceroute.Hop `json:",omitempty"`
}

type Test struct {
	Status   string
	Protocol string `json:",omitempty"`
	Client   string `json:",omitempty"`
	Resolver string `json:",omitempty"`
	SrcIP    string `json:",omitempty"`
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

	if r.Resolvers = host.DNS(); len(r.Resolvers) > 0 {
		fmt.Println("Resolvers: ", strings.Join(r.Resolvers, ", "))
		net.DefaultResolver.PreferGo = true
		d := &net.Dialer{}
		net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, net.JoinHostPort(r.Resolvers[0], "53"))
		}
	}

	r.HasV6 = hasIPv6()
	r.Test = test()
	r.ULLPrimary = pop("ultra low latency primary IPv4", "ipv4.dns1.nextdns.io")
	r.ULLSecondary = pop("ultra low latency secondary IPv4", "ipv4.dns2.nextdns.io")
	r.Primary = pop("anycast primary IPv4", "45.90.28.0")
	r.Secondary = pop("anycast secondary IPv4", "45.90.30.0")
	if r.HasV6 {
		r.ULLPrimary6 = pop("ultra low latency primary IPv6", "ipv6.dns1.nextdns.io")
		r.ULLSecondary6 = pop("ultra low latency secondary IPv6", "ipv6.dns2.nextdns.io")
		r.Primary6 = pop("anycast primary IPv6", "2a07:a8c0::")
		r.Secondary6 = pop("anycast secondary IPv6", "2a07:a8c1::")
	}
	r.Top = pings(r.HasV6)
	r.ULLPrimaryTraceroute, r.ULLPrimaryTraceback = trace("ultra low latency primary IPv4", "ipv4.dns1.nextdns.io")
	r.ULLSecondaryTraceroute, r.ULLSecondaryTraceback = trace("ultra low latency secondary IPv4", "ipv4.dns2.nextdns.io")
	r.PrimaryTraceroute, r.PrimaryTraceback = trace("anycast primary IPv4", "45.90.28.0")
	r.SecondaryTraceroute, r.SecondaryTraceback = trace("anycast secondary IPv4", "45.90.30.0")
	if r.HasV6 {
		r.ULLPrimaryTraceroute6, r.ULLPrimaryTraceback6 = trace("ultra low latency primary IPv6", "ipv6.dns1.nextdns.io")
		r.ULLSecondaryTraceroute6, r.ULLSecondaryTraceback6 = trace("ultra low latency secondary IPv6", "ipv6.dns2.nextdns.io")
		r.PrimaryTraceroute6, r.PrimaryTraceback6 = trace("anycast primary IPv6", "2a07:a8c0::")
		r.SecondaryTraceroute6, r.SecondaryTraceback6 = trace("anycast secondary IPv6", "2a07:a8c1::")
	}

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
	c, err := net.Dial("tcp", "[2620:fe::fe]:443")
	if c != nil {
		c.Close()
	}
	v6 := err == nil
	fmt.Printf(indent("available: %v\n"), v6)
	return v6
}

type traceResult struct {
	hops  []traceroute.Hop
	lines []string
	err   error
}

func trace(name string, dest string) ([]traceroute.Hop, []traceroute.Hop) {
	ip, err := resolveIP(dest)
	if err != nil {
		fmt.Printf(indent("Traceroute error: %v\n"), err)
		return nil, nil
	}
	fmt.Printf("Processing traceroute and traceback for %s (%s)\n", name, ip)
	var wg sync.WaitGroup
	var traceRes, tracebackRes traceResult
	wg.Add(2)
	go func() {
		defer wg.Done()
		traceRes = runTraceroute(ip)
	}()
	go func() {
		defer wg.Done()
		tracebackRes = runTraceback(ip)
	}()
	wg.Wait()

	fmt.Printf("Traceroute for %s (%s)\n", name, ip)
	for _, line := range traceRes.lines {
		fmt.Println(indent(line))
	}
	if traceRes.err != nil {
		fmt.Printf(indent("error: %v\n"), traceRes.err)
	}

	fmt.Printf("Traceback for %s (%s)\n", name, ip)
	for _, line := range tracebackRes.lines {
		fmt.Println(indent(line))
	}
	if tracebackRes.err != nil {
		fmt.Printf(indent("error: %v\n"), tracebackRes.err)
	}

	return traceRes.hops, tracebackRes.hops
}

func resolveIP(dest string) (net.IP, error) {
	if ip := net.ParseIP(dest); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", dest)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP for host")
	}
	return ips[0], nil
}

func runTraceroute(ip net.IP) traceResult {
	var t traceroute.Tracer
	c := make(chan traceroute.Hop)
	var hops []traceroute.Hop
	var lines []string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for hop := range c {
			hops = append(hops, hop)
			lines = append(lines, hop.String())
		}
	}()
	err := t.Trace(context.Background(), ip, c)
	close(c)
	wg.Wait()
	return traceResult{
		hops:  hops,
		lines: lines,
		err:   err,
	}
}

func runTraceback(ip net.IP) traceResult {
	hops, err := traceback.Fetch(&http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), "443"))
			},
		},
	}, "https://dns.nextdns.io/traceback")
	lines := make([]string, 0, len(hops))
	for _, hop := range hops {
		lines = append(lines, hop.String())
	}
	return traceResult{
		hops:  hops,
		lines: lines,
		err:   err,
	}
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
	if t.Client == "" {
		t.Client, t.SrcIP = t.SrcIP, ""
	}
	fmt.Println(indent(t.String()))
	return t
}

func pop(name, target string) *Ping {
	fmt.Printf("Fetching PoP name for %s (%s)\n", name, target)
	req, _ := http.NewRequest("GET", "https://dns.nextdns.io/info", nil)
	cl := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, net.JoinHostPort(target, "443"))
			},
		},
	}
	res, err := cl.Do(req)
	if err != nil {
		fmt.Printf("Fetch error: %v\n", err)
		return &Ping{
			Pop:      "err: " + err.Error(),
			Protocol: 0,
			RTT:      0,
		}
	}
	defer res.Body.Close()
	var p Ping
	j := json.NewDecoder(res.Body)
	if err := j.Decode(&p); err != nil {
		fmt.Printf(indent("Cannot decode response: %v\n"), err)
	}
	p.RTT *= 1000
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
	p.RTT *= 1000
	return p

}

func indent(s string) string {
	return "  " + strings.TrimRight(strings.ReplaceAll(s, "\n", "\n  "), " ")
}
