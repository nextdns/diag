package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/nextdns/nextdns/host"
)

const diagnosticEndpoint = "https://api.nextdns.io/diagnostic"

// Public resolvers used only to deliver the report when the system
// resolver cannot. The diagnostic itself still queries through the
// resolver under test.
var bootstrapDNSServers = []string{
	"1.1.1.1",
	"8.8.8.8",
	"9.9.9.9",
	"2606:4700:4700::1111",
	"2001:4860:4860::8888",
}

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

	rawResolvers := host.DNS()
	r.Resolvers = normalizeResolvers(rawResolvers)
	if len(r.Resolvers) == 0 {
		// Keep the raw values in the report when none of them are usable addresses.
		r.Resolvers = rawResolvers
	} else {
		fmt.Println("Resolvers: ", strings.Join(r.Resolvers, ", "))
		// Query the literal system resolvers. host.DNS sometimes returns every
		// address in one string ("45.90.28.219 45.90.30.219"); dialing that
		// string makes the final POST fail with "no such host" or a lookup timeout.
		net.DefaultResolver.PreferGo = true
		net.DefaultResolver.Dial = fixedDNSDial(r.Resolvers)
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
	r.ULLPrimaryTraceroute = trace("ultra low latency primary IPv4", "ipv4.dns1.nextdns.io")
	r.ULLSecondaryTraceroute = trace("ultra low latency secondary IPv4", "ipv4.dns2.nextdns.io")
	r.PrimaryTraceroute = trace("anycast primary IPv4", "45.90.28.0")
	r.SecondaryTraceroute = trace("anycast secondary IPv4", "45.90.30.0")
	if r.HasV6 {
		r.ULLPrimaryTraceroute6 = trace("ultra low latency primary IPv6", "ipv6.dns1.nextdns.io")
		r.ULLSecondaryTraceroute6 = trace("ultra low latency secondary IPv6", "ipv6.dns2.nextdns.io")
		r.PrimaryTraceroute6 = trace("anycast primary IPv6", "2a07:a8c0::")
		r.SecondaryTraceroute6 = trace("anycast secondary IPv6", "2a07:a8c1::")
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
	id, err := postDiagnostic(b)
	if err != nil {
		var status *postStatusError
		if errors.As(err, &status) {
			fmt.Printf("Post unsuccessful: status %d\n", status.code)
			fmt.Fprint(os.Stderr, status.body)
			os.Exit(1)
		}
		fmt.Printf("Post unsuccessful: %v\n", err)
		fmt.Println("Please report this issue on https://github.com/nextdns/diag")
		os.Exit(1)
	}
	fmt.Printf("Posted: https://nextdns.io/diag/%s\n", id)
	if runtime.GOOS == "windows" {
		fmt.Scanln()
	}
}

// normalizeResolvers splits resolver lists into individual IP addresses.
// macOS ipconfig and systemd lease files report every server in one string,
// separated by spaces. Dialing that whole string is not a DNS lookup.
func normalizeResolvers(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, item := range in {
		for _, field := range strings.Fields(strings.ReplaceAll(item, ",", " ")) {
			ip := net.ParseIP(field)
			if ip == nil {
				continue
			}
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// literalDialer connects only to IP literals. A hostname here would be
// resolved by DefaultResolver and call back into this dialer.
func literalDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("dns server address must be a literal ip")
			},
		},
	}
}

// fixedDNSDial always queries the first system resolver. The address argument
// is the nameserver from resolv.conf, which is intentionally not used: on
// some platforms that file is not the resolver the host is actually using.
func fixedDNSDial(servers []string) func(context.Context, string, string) (net.Conn, error) {
	return dnsDial(servers, "53", false)
}

func rotatingDNSDial(servers []string) func(context.Context, string, string) (net.Conn, error) {
	return dnsDial(servers, "53", true)
}

func dnsDial(servers []string, port string, rotate bool) func(context.Context, string, string) (net.Conn, error) {
	var mu sync.Mutex
	var n int
	d := literalDialer()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if len(servers) == 0 {
			return nil, errors.New("no dns servers")
		}
		server := servers[0]
		if rotate {
			mu.Lock()
			server = servers[n%len(servers)]
			n++
			mu.Unlock()
		}
		return d.DialContext(ctx, network, net.JoinHostPort(server, port))
	}
}

type postStatusError struct {
	code int
	body string
}

func (e *postStatusError) Error() string {
	return fmt.Sprintf("status %d", e.code)
}

func shouldRetryPost(err error) bool {
	if err == nil {
		return false
	}
	var status *postStatusError
	if errors.As(err, &status) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func postDiagnostic(body []byte) (string, error) {
	return postWithClients(body, diagnosticEndpoint, []*http.Client{
		{Timeout: 30 * time.Second},
		bootstrapClient(),
	})
}

func postWithClients(body []byte, endpoint string, clients []*http.Client) (string, error) {
	var first error
	for i, client := range clients {
		id, err := postJSON(client, endpoint, body)
		if err == nil {
			return id, nil
		}
		if i == 0 {
			first = err
		}
		if i == len(clients)-1 || !shouldRetryPost(err) {
			if i > 0 && first != nil {
				return "", fmt.Errorf("%v; fallback: %v", first, err)
			}
			return "", err
		}
		fmt.Println("Post failed, retrying via public DNS...")
	}
	return "", errors.New("no http client")
}

func postJSON(client *http.Client, endpoint string, body []byte) (string, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", &postStatusError{code: res.StatusCode, body: string(msg)}
	}
	var result struct {
		ID string
	}
	_ = json.NewDecoder(res.Body).Decode(&result)
	return result.ID, nil
}

func bootstrapClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial:     rotatingDNSDial(bootstrapDNSServers),
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				name, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if name != "api.nextdns.io" {
					return dialer.DialContext(ctx, network, address)
				}
				ips, err := resolver.LookupIP(ctx, "ip", name)
				if err != nil {
					return nil, err
				}
				var last error
				for _, ip := range ips {
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
					if err == nil {
						return conn, nil
					}
					last = err
				}
				if last == nil {
					last = fmt.Errorf("no ip for %s", name)
				}
				return nil, last
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
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

func trace(name string, dest string) []traceroute.Hop {
	ip, err := resolveIP(dest)
	if err != nil {
		fmt.Printf(indent("Traceroute error: %v\n"), err)
		return nil
	}
	fmt.Printf("Traceroute for %s (%s)\n", name, ip)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var t traceroute.Tracer
	// Trace can return every collected hop without blocking after cancellation.
	c := make(chan traceroute.Hop, traceroute.DefaultMaxHops)
	err = t.Trace(ctx, ip, c)
	close(c)
	var hops []traceroute.Hop
	for hop := range c {
		hops = append(hops, hop)
		fmt.Println(indent(hop.String()))
	}
	if err != nil {
		fmt.Printf(indent("error: %v\n"), err)
	}
	return hops
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
	res, err := http.Get("https://dns.nextdns.io/servers")
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
