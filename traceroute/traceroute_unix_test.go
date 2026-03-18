//go:build !windows
// +build !windows

package traceroute

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestTraceWithConnProbesInRounds(t *testing.T) {
	dest := net.IPv4(203, 0, 113, 10)
	conn := &fakePacketConn{
		family: 4,
		script: func(call writeCall) []readAction {
			switch call.ttl {
			case 1:
				return []readAction{{
					packet: ipv4TimeExceededPacket(call.id, call.seq),
					addr:   &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)},
				}}
			case 2:
				return []readAction{{
					packet: ipv4EchoReplyPacket(call.id, call.seq),
					addr:   &net.IPAddr{IP: dest},
				}}
			default:
				t.Fatalf("unexpected ttl %d", call.ttl)
				return nil
			}
		},
	}
	hops, err := collectTrace(Tracer{
		MaxHops:    5,
		HopTimeout: time.Second,
		Probes:     3,
	}, dest, conn)
	if err != nil {
		t.Fatalf("Trace() error = %v", err)
	}
	if got, want := conn.hopLimits, []int{1, 2, 1, 2, 1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hop limits = %v, want %v", got, want)
	}
	if got, want := len(hops), 2; got != want {
		t.Fatalf("len(hops) = %d, want %d", got, want)
	}
	for i, hop := range hops {
		if got, want := hop.Seq, i+1; got != want {
			t.Fatalf("hop %d seq = %d, want %d", i, got, want)
		}
		if got, want := len(hop.Info), 3; got != want {
			t.Fatalf("hop %d samples = %d, want %d", i, got, want)
		}
	}
	if got, want := hops[0].IPs(), []net.IP{net.IPv4(192, 0, 2, 1)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hop 1 IPs = %v, want %v", got, want)
	}
	if got, want := hops[1].IPs(), []net.IP{dest}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hop 2 IPs = %v, want %v", got, want)
	}
}

func TestTraceWithConnTimeoutDoesNotResetOnUnmatchedPacket(t *testing.T) {
	conn := &fakePacketConn{
		family: 4,
		script: func(call writeCall) []readAction {
			return []readAction{
				{
					packet: ipv4TimeExceededPacket(call.id, call.seq+1),
					addr:   &net.IPAddr{IP: net.IPv4(192, 0, 2, 99)},
				},
				{err: timeoutError{}},
			}
		},
	}
	hops, err := collectTrace(Tracer{
		MaxHops:    1,
		HopTimeout: time.Millisecond,
		Probes:     1,
	}, net.IPv4(203, 0, 113, 11), conn)
	if err != nil {
		t.Fatalf("Trace() error = %v", err)
	}
	if got, want := len(hops), 1; got != want {
		t.Fatalf("len(hops) = %d, want %d", got, want)
	}
	if got, want := hops[0].RTTs(), []time.Duration{-1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RTTs = %v, want %v", got, want)
	}
	if len(conn.deadlines) < 2 {
		t.Fatalf("expected at least two deadlines, got %d", len(conn.deadlines))
	}
	if !conn.deadlines[0].Equal(conn.deadlines[1]) {
		t.Fatalf("deadline reset from %v to %v", conn.deadlines[0], conn.deadlines[1])
	}
}

func TestTraceWithConnPropagatesParseErrors(t *testing.T) {
	conn := &fakePacketConn{
		family: 4,
		script: func(call writeCall) []readAction {
			return []readAction{{
				packet: []byte{1, 2, 3},
				addr:   &net.IPAddr{IP: net.IPv4(192, 0, 2, 2)},
			}}
		},
	}
	_, err := collectTrace(Tracer{
		MaxHops:    1,
		HopTimeout: time.Second,
		Probes:     1,
	}, net.IPv4(203, 0, 113, 12), conn)
	if err == nil {
		t.Fatal("Trace() error = nil, want parse error")
	}
	if !strings.Contains(err.Error(), "cannot parse ICMP packet") {
		t.Fatalf("Trace() error = %v, want parse error", err)
	}
}

func collectTrace(t Tracer, dest net.IP, conn packetConn) ([]Hop, error) {
	size := t.MaxHops
	if size == 0 {
		size = DefaultMaxHops
	}
	c := make(chan Hop, size)
	err := t.traceWithConn(context.Background(), dest, c, conn)
	close(c)
	var hops []Hop
	for hop := range c {
		hops = append(hops, hop)
	}
	return hops, err
}

type fakePacketConn struct {
	family      int
	currentTTL  int
	hopLimits   []int
	deadlines   []time.Time
	readActions []readAction
	script      func(writeCall) []readAction
}

type writeCall struct {
	ttl int
	id  int
	seq int
}

type readAction struct {
	packet []byte
	addr   net.Addr
	err    error
}

func (c *fakePacketConn) Close() error {
	return nil
}

func (c *fakePacketConn) Write(b []byte, dst net.Addr) (int, error) {
	msg, err := icmp.ParseMessage(icmpProto(c.family), b)
	if err != nil {
		return 0, err
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return 0, nil
	}
	if c.script != nil {
		c.readActions = append(c.readActions, c.script(writeCall{
			ttl: c.currentTTL,
			id:  echo.ID,
			seq: echo.Seq,
		})...)
	}
	return len(b), nil
}

func (c *fakePacketConn) Read(b []byte) (int, net.Addr, error) {
	if len(c.readActions) == 0 {
		return 0, nil, timeoutError{}
	}
	action := c.readActions[0]
	c.readActions = c.readActions[1:]
	if action.err != nil {
		return 0, action.addr, action.err
	}
	n := copy(b, action.packet)
	return n, action.addr, nil
}

func (c *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func (c *fakePacketConn) SetHopLimit(hoplim int) error {
	c.currentTTL = hoplim
	c.hopLimits = append(c.hopLimits, hoplim)
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func ipv4EchoReplyPacket(id, seq int) []byte {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:  id,
			Seq: seq,
		},
	}
	packet, err := msg.Marshal(nil)
	if err != nil {
		panic(err)
	}
	return packet
}

func ipv4TimeExceededPacket(id, seq int) []byte {
	inner := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:  id,
			Seq: seq,
			Data: []byte{
				0, 1, 2, 3,
			},
		},
	}
	innerPacket, err := inner.Marshal(nil)
	if err != nil {
		panic(err)
	}
	header, err := (&ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(innerPacket),
		TTL:      1,
		Protocol: protocolICMP,
		Src:      net.IPv4(198, 51, 100, 1),
		Dst:      net.IPv4(203, 0, 113, 1),
	}).Marshal()
	if err != nil {
		panic(err)
	}
	outer := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0,
		Body: &icmp.TimeExceeded{
			Data: append(header, innerPacket...),
		},
	}
	packet, err := outer.Marshal(nil)
	if err != nil {
		panic(err)
	}
	return packet
}
