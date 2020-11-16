package traceroute

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	DefaultPacketSize = 52
	DefaultHopTimeout = 5 * time.Second
	DefaultMaxHops    = 20
)

type Tracer struct {
	PacketSize uint16
	HopTimeout time.Duration
	MaxHops    int
}

// Hop represents a network hop in a traceroute result
type Hop struct {
	Seq  int
	Info []HopInfo
}

func (h Hop) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%3d ", h.Seq)
	first := true
	for _, ip := range h.IPs() {
		if !first {
			sb.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&sb, "%14s", ip.String())
	}
	if first {
		sb.WriteString("               ")
	} else {
		sb.WriteByte(' ')
	}
	for _, rtt := range h.RTTs() {
		if rtt == -1 {
			sb.WriteString("   *  ")
		} else {
			fmt.Fprintf(&sb, " %3dms", rtt/time.Millisecond)
		}
	}
	return sb.String()
}

func (h Hop) IPs() []net.IP {
	var ips []net.IP
	for _, hop := range h.Info {
		ip := hop.IP
		if ip == nil {
			continue
		}
		var exists bool
		for _, _ip := range ips {
			if ip.Equal(_ip) {
				exists = true
				break
			}
		}
		if !exists {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (h Hop) RTTs() []time.Duration {
	var rtts []time.Duration
	for _, hop := range h.Info {
		rtts = append(rtts, hop.RTT)
	}
	return rtts
}

type HopInfo struct {
	IP  net.IP
	RTT time.Duration
}
