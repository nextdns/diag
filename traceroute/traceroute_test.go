package traceroute

import (
	"net"
	"testing"
	"time"
)

func TestHopString(t *testing.T) {
	hop := Hop{
		Seq: 1,
		Info: []HopInfo{
			{IP: net.ParseIP("10.0.0.1"), RTT: 12 * time.Millisecond},
			{RTT: -1},
			{IP: net.ParseIP("10.0.0.1"), RTT: 15 * time.Millisecond},
		},
	}

	if got, want := hop.String(), "  1       10.0.0.1   12ms   *    15ms"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
