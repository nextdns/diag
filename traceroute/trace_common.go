package traceroute

import (
	"context"
	"net"
	"time"
)

type traceConfig struct {
	family     int
	packetSize int
	maxHops    int
	hopTimeout time.Duration
	probes     int
}

type probeFunc func(ttl int, timeout time.Duration) (HopInfo, bool, error)

func (t *Tracer) traceConfig(dest net.IP) traceConfig {
	packetSize := int(t.PacketSize)
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
	return traceConfig{
		family:     traceFamily(dest),
		packetSize: packetSize,
		maxHops:    maxHops,
		hopTimeout: hopTimeout,
		probes:     probes,
	}
}

func traceFamily(dest net.IP) int {
	if dest.To4() != nil {
		return 4
	}
	return 6
}

func (t *Tracer) traceWithFunc(ctx context.Context, cfg traceConfig, c chan Hop, probe probeFunc) error {
	hops := make([]Hop, cfg.maxHops)
	for i := range hops {
		hops[i].Seq = i + 1
	}

	lastHop := cfg.maxHops
	complete := false
	for round := 0; round < cfg.probes; round++ {
		hopLimit := cfg.maxHops
		if complete {
			hopLimit = lastHop
		}
		for ttl := 1; ttl <= hopLimit; ttl++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			info, last, err := probe(ttl, cfg.hopTimeout)
			if err != nil {
				return err
			}
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
