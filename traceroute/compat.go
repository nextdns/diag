package traceroute

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

// packetConn provides a common interface for IPv4 and IPv6 packetConn
type packetConn interface {
	io.Closer
	Write([]byte, net.Addr) (int, error)
	Read(b []byte) (n int, src net.Addr, err error)
	SetReadDeadline(t time.Time) error
	SetHopLimit(hoplim int) error
}

type packetConn4 struct {
	*ipv4.PacketConn
}

func (p packetConn4) Write(b []byte, dst net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, nil, dst)
}
func (p packetConn4) Read(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = p.PacketConn.ReadFrom(b)
	return
}
func (p packetConn4) SetHopLimit(hoplim int) error {
	return p.PacketConn.SetTTL(hoplim)
}

type packetConn6 struct {
	*ipv6.PacketConn
}

func (p packetConn6) Write(b []byte, dst net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, nil, dst)
}
func (p packetConn6) Read(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = p.PacketConn.ReadFrom(b)
	return
}
func newPacketConn(family int) (conn packetConn, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("newPacketConn(%d): %w", family, err)
		}
	}()
	switch family {
	case 4:
		c, err := icmp.ListenPacket("ip4:icmp", "")
		if err != nil {
			return nil, err
		}
		p := c.IPv4PacketConn()
		if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
			return nil, err
		}
		return packetConn4{p}, nil
	case 6:
		c, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
		if err != nil {
			return nil, err
		}
		p := c.IPv6PacketConn()
		if err := p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		return packetConn6{p}, nil
	default:
		return nil, errors.New("unsupported network")
	}
}

func icmpProto(family int) int {
	switch family {
	case 4:
		return protocolICMP
	case 6:
		return protocolIPv6ICMP
	default:
		panic("invalid family")
	}
}

func icmpEchoType(family int) icmp.Type {
	switch family {
	case 4:
		return ipv4.ICMPTypeEcho
	case 6:
		return ipv6.ICMPTypeEchoRequest
	default:
		panic("invalid family")
	}
}

func ipPayloadOffset(family int, b []byte) (int, error) {
	var l int
	switch family {
	case 4:
		h, err := ipv4.ParseHeader(b)
		if err != nil {
			return -1, err
		}
		l = h.Len
	case 6:
		h, err := ipv6.ParseHeader(b)
		if err != nil {
			return -1, err
		}
		l = len(b) - h.PayloadLen
	default:
		panic("invalid family")
	}
	return l, nil
}

func isICMPEchoReply(t icmp.Type) bool {
	return t == ipv4.ICMPTypeEchoReply || t == ipv6.ICMPTypeEchoReply
}

func isICMPTimeExceeded(t icmp.Type) bool {
	return t == ipv4.ICMPTypeTimeExceeded || t == ipv6.ICMPTypeTimeExceeded
}

func isICMPDestinationUnreachable(t icmp.Type) bool {
	return t == ipv4.ICMPTypeDestinationUnreachable || t == ipv6.ICMPTypeDestinationUnreachable
}
