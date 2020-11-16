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
	Seq  int
	ID   int
	IP   net.IP
	Last bool
}

func (t *Tracer) Trace(ctx context.Context, dest net.IP, c chan Hop) error {
	family := 4
	if dest.To4() == nil {
		family = 6
	}
	dst := net.IPAddr{IP: dest}

	conn, err := newPacketConn(family)
	if err != nil {
		return err
	}
	defer conn.Close()

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

	// Prepare IMCP packet
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

	pkt := make(chan packetInfo)
	go run(conn, family, pkt)

	seq := uint16(rand.Intn(0xffff))

	var complete bool
	for i := 1; i <= maxHops && !complete; i++ {
		var h = Hop{Seq: i}
		for j := 0; j < 3; j++ {
			wmb.Seq = int(seq)
			seq++
			wb, err := wm.Marshal(nil)
			if err != nil {
				return fmt.Errorf("cannot marshal ICMP packet: %v", err)
			}
			if err := conn.SetHopLimit(i); err != nil {
				return fmt.Errorf("cannot set hop limit: %v", err)
			}
			start := time.Now()
			if _, err := conn.Write(wb, &dst); err != nil {
				return fmt.Errorf("cannot write ICMP packet: %v", err)
			}
			for {
				select {
				case p := <-pkt:
					if wmb.Seq != p.Seq || wmb.ID != p.ID {
						continue
					}
					h.Info = append(h.Info, HopInfo{
						IP:  p.IP,
						RTT: time.Since(start),
					})
					if p.Last {
						complete = true
					}
				case <-time.After(hopTimeout):
					h.Info = append(h.Info, HopInfo{RTT: -1})
				case <-ctx.Done():
					return ctx.Err()
				}
				break
			}
		}
		c <- h
	}

	return nil
}

func run(conn packetConn, family int, c chan packetInfo) error {
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.Read(buf)
		if err != nil {
			return err
		}
		var nrb = buf[:n]
		id, seq, last, err := handleICMPPacket(&nrb, family)
		if err != nil {
			return err
		}
		c <- packetInfo{
			ID:   id,
			Seq:  seq,
			IP:   netAddrToIP(peer),
			Last: last,
		}
	}
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

func handleICMPPacket(rb *[]byte, family int) (id, seq int, last bool, err error) {
	proto := icmpProto(family)
	rm, err := icmp.ParseMessage(proto, *rb)
	if err != nil {
		return 0, 0, false, err
	}
	if !isICMPEchoReply(rm.Type) && !isICMPTimeExceeded(rm.Type) && !isICMPDestinationUnreachable(rm.Type) {
		// not interested
		return 0, 0, false, nil
	}
	switch pkt := rm.Body.(type) {
	case *icmp.TimeExceeded:
		id, seq, err = unwrapICMPPayload(&pkt.Data, family)
		return
	case *icmp.DstUnreach:
		id, seq, err = unwrapICMPPayload(&pkt.Data, family)
		last = true
		return
	case *icmp.Echo:
		return pkt.ID, pkt.Seq, true, nil
	}
	return 0, 0, false, nil
}

func unwrapICMPPayload(rb *[]byte, family int) (id, seq int, err error) {
	proto := icmpProto(family)

	// Unwrap embedded ICMP packet
	o, err := ipPayloadOffset(family, *rb)
	if err != nil {
		return 0, 0, err
	}
	if o < 0 || o >= len(*rb) {
		// can't find payload, should not happen though
		return 0, 0, errors.New("Can't find ICMP payload")
	}

	rm, err := icmp.ParseMessage(proto, (*rb)[o:])
	if err != nil {
		return 0, 0, err
	}
	rmb, ok := rm.Body.(*icmp.Echo)
	if !ok {
		// may be udp or other, doesnt belong to us
		return 0, 0, nil
	}
	return rmb.ID, rmb.Seq, nil
}
