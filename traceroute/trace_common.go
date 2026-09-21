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
	var traceErr error
traceLoop:
	for round := 0; round < cfg.probes; round++ {
		hopLimit := cfg.maxHops
		if complete {
			hopLimit = lastHop
		}
		for ttl := 1; ttl <= hopLimit; ttl++ {
			if err := traceContextError(ctx); err != nil {
				traceErr = err
				break traceLoop
			}
			info, last, err := probe(ttl, cfg.hopTimeout)
			if err != nil {
				traceErr = err
				break traceLoop
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
		if len(hop.Info) == 0 {
			continue
		}
		// Preserve partial results after cancellation when the caller has room
		// for them, but never wait for a receiver on a canceled context.
		select {
		case c <- hop:
			continue
		default:
		}
		select {
		case c <- hop:
		case <-ctx.Done():
			if traceErr != nil {
				return traceErr
			}
			return ctx.Err()
		}
	}
	if traceErr != nil {
		return traceErr
	}
	return traceContextError(ctx)
}

func traceContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// An I/O deadline can fire before the context's timer is scheduled.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
