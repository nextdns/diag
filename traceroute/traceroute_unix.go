//go:build !windows
// +build !windows

package traceroute

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
)

type packetInfo struct {
	Seq   int
	ID    int
	Peer  net.Addr
	Last  bool
	Valid bool
}

func (t *Tracer) Trace(ctx context.Context, dest net.IP, c chan Hop) error {
	family := 4
	if dest.To4() == nil {
		family = 6
	}

	conn, err := newPacketConn(family)
	if err != nil {
		return err
	}
	defer conn.Close()
	return t.traceWithConn(ctx, dest, c, conn)
}

func (t *Tracer) traceWithConn(ctx context.Context, dest net.IP, c chan Hop, conn packetConn) error {
	family := 4
	if dest.To4() == nil {
		family = 6
	}
	dst := net.IPAddr{IP: dest}

	packetSize := t.PacketSize
	if packetSize == 0 {
		packetSize = DefaultPacketSize
	}
	maxHops := t.MaxHops
	if maxHops == 0 {
		maxHops = DefaultMaxHops
	}
	hopTimeout := t.HopTimeout
	if hopTimeout == 0 {
		hopTimeout = DefaultHopTimeout
	}
	probes := t.Probes
	if probes == 0 {
		probes = DefaultProbes
	}

	// Prepare ICMP packet.
	id := rand.Intn(0xffff)
	wmb := icmp.Echo{
		ID:   id,
		Data: make([]byte, packetSize),
	}
	wm := icmp.Message{
		Type: icmpEchoType(family),
		Code: 0,
		Body: &wmb,
	}

	seq := uint16(rand.Intn(0xffff))

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	hops := make([]Hop, maxHops)
	for i := range hops {
		hops[i].Seq = i + 1
	}

	lastHop := maxHops
	complete := false
	for round := 0; round < probes; round++ {
		hopLimit := maxHops
		if complete {
			hopLimit = lastHop
		}
		for ttl := 1; ttl <= hopLimit; ttl++ {
			info, last, err := t.probe(ctx, conn, family, ttl, &dst, &wm, &wmb, seq, hopTimeout)
			if err != nil {
				return err
			}
			seq++
			hops[ttl-1].Info = append(hops[ttl-1].Info, info)
			if last {
				complete = true
				lastHop = ttl
				break
			}
		}
	}

	if complete {
		hops = hops[:lastHop]
	}
	for _, hop := range hops {
		c <- hop
	}

	return nil
}

func (t *Tracer) probe(ctx context.Context, conn packetConn, family int, ttl int, dst net.Addr, wm *icmp.Message, wmb *icmp.Echo, seq uint16, timeout time.Duration) (HopInfo, bool, error) {
	wmb.Seq = int(seq)
	wb, err := wm.Marshal(nil)
	if err != nil {
		return HopInfo{}, false, fmt.Errorf("cannot marshal ICMP packet: %v", err)
	}
	if err := conn.SetHopLimit(ttl); err != nil {
		return HopInfo{}, false, fmt.Errorf("cannot set hop limit: %v", err)
	}
	start := time.Now()
	if _, err := conn.Write(wb, dst); err != nil {
		return HopInfo{}, false, fmt.Errorf("cannot write ICMP packet: %v", err)
	}
	deadline := start.Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return HopInfo{}, false, err
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return HopInfo{}, false, fmt.Errorf("cannot set read deadline: %v", err)
		}
		p, err := readPacket(conn, family)
		if err != nil {
			if isTimeout(err) {
				return HopInfo{RTT: -1}, false, nil
			}
			if err := ctx.Err(); err != nil {
				return HopInfo{}, false, err
			}
			return HopInfo{}, false, err
		}
		if !p.Valid || p.ID != wmb.ID || p.Seq != wmb.Seq {
			continue
		}
		return HopInfo{
			IP:  netAddrToIP(p.Peer),
			RTT: time.Since(start),
		}, p.Last, nil
	}
}

func readPacket(conn packetConn, family int) (packetInfo, error) {
	buf := make([]byte, 1500)
	n, peer, err := conn.Read(buf)
	if err != nil {
		return packetInfo{}, err
	}
	id, seq, last, ok, err := handleICMPPacket(buf[:n], family)
	if err != nil {
		return packetInfo{}, fmt.Errorf("cannot parse ICMP packet: %v", err)
	}
	if !ok {
		return packetInfo{Peer: peer}, nil
	}
	return packetInfo{
		ID:    id,
		Seq:   seq,
		Peer:  peer,
		Last:  last,
		Valid: true,
	}, nil
}

func netAddrToIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		if ip := v.IP; ip != nil {
			return ip
		}
	case *net.IPAddr:
		if ip := v.IP; ip != nil {
			return ip
		}
	}
	return nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func handleICMPPacket(rb []byte, family int) (id, seq int, last bool, ok bool, err error) {
	proto := icmpProto(family)
	rm, err := icmp.ParseMessage(proto, rb)
	if err != nil {
		return 0, 0, false, false, err
	}
	if !isICMPEchoReply(rm.Type) && !isICMPTimeExceeded(rm.Type) && !isICMPDestinationUnreachable(rm.Type) {
		// not interested
		return 0, 0, false, false, nil
	}
	switch pkt := rm.Body.(type) {
	case *icmp.TimeExceeded:
		id, seq, ok, err = unwrapICMPPayload(pkt.Data, family)
		return
	case *icmp.DstUnreach:
		id, seq, ok, err = unwrapICMPPayload(pkt.Data, family)
		last = true
		return
	case *icmp.Echo:
		return pkt.ID, pkt.Seq, true, true, nil
	}
	return 0, 0, false, false, nil
}

func unwrapICMPPayload(rb []byte, family int) (id, seq int, ok bool, err error) {
	proto := icmpProto(family)

	// Unwrap embedded ICMP packet
	o, err := ipPayloadOffset(family, rb)
	if err != nil {
		return 0, 0, false, err
	}
	if o < 0 || o >= len(rb) {
		// can't find payload, should not happen though
		return 0, 0, false, errors.New("cannot find ICMP payload")
	}

	rm, err := icmp.ParseMessage(proto, rb[o:])
	if err != nil {
		return 0, 0, false, err
	}
	rmb, ok := rm.Body.(*icmp.Echo)
	if !ok {
		// may be UDP or other, does not belong to us.
		return 0, 0, false, nil
	}
	return rmb.ID, rmb.Seq, true, nil
}
