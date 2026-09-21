package traceroute

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestTraceWithFuncPreservesPartialResults(t *testing.T) {
	for _, cancelTrace := range []bool{false, true} {
		t.Run(map[bool]string{false: "probe error", true: "canceled"}[cancelTrace], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantErr := errors.New("probe failed")
			if cancelTrace {
				wantErr = context.Canceled
			}
			c := make(chan Hop, 3)
			calls := 0
			err := (&Tracer{}).traceWithFunc(ctx, traceConfig{maxHops: 3, probes: 3}, c,
				func(ttl int, timeout time.Duration) (HopInfo, bool, error) {
					calls++
					if calls == 5 {
						if cancelTrace {
							cancel()
						}
						return HopInfo{}, false, wantErr
					}
					return HopInfo{RTT: time.Millisecond}, false, nil
				})
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			close(c)
			var samples []int
			for hop := range c {
				samples = append(samples, len(hop.Info))
				if hop.Seq != len(samples) {
					t.Fatalf("hop sequence = %d, want %d", hop.Seq, len(samples))
				}
			}
			if !reflect.DeepEqual(samples, []int{2, 1, 1}) {
				t.Fatalf("samples = %v, want [2 1 1]", samples)
			}
		})
	}
}

func TestTraceWithFuncCancellationDuringDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := make(chan Hop)
	done := make(chan error, 1)
	go func() {
		done <- (&Tracer{}).traceWithFunc(ctx, traceConfig{maxHops: 2, probes: 1}, c,
			func(int, time.Duration) (HopInfo, bool, error) {
				return HopInfo{RTT: time.Millisecond}, false, nil
			})
	}()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive first hop")
	}
	// Stop receiving while Trace still has a hop to send.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Trace blocked sending results after cancellation")
	}
}

func TestTraceWithFuncCancellationOnFinalProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := make(chan Hop, 3)
	err := (&Tracer{}).traceWithFunc(ctx, traceConfig{maxHops: 3, probes: 1}, c,
		func(int, time.Duration) (HopInfo, bool, error) {
			cancel()
			return HopInfo{RTT: time.Millisecond}, true, nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(c) != 1 {
		t.Fatalf("collected hops = %d, want 1", len(c))
	}
}

func TestTraceWithFuncExpiredDeadlineBeforeContextTimer(t *testing.T) {
	ctx := &delayedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
	c := make(chan Hop, 1)
	err := (&Tracer{}).traceWithFunc(ctx, traceConfig{maxHops: 1, probes: 1}, c,
		func(int, time.Duration) (HopInfo, bool, error) {
			// Simulate an I/O timeout before the context timer sets ctx.Err().
			ctx.deadline = time.Now().Add(-time.Second)
			return HopInfo{RTT: -1}, false, nil
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if len(c) != 1 {
		t.Fatalf("collected hops = %d, want 1", len(c))
	}
}

type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c *delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
