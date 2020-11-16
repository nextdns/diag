package traceroute

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func Test_parseTracertLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		hop  Hop
		ok   bool
	}{
		{"Success v4",
			"  1     8 ms     6 ms    10 ms  45.90.28.0",
			Hop{
				Seq: 1,
				Info: []HopInfo{
					{net.ParseIP("45.90.28.0"), 8 * time.Millisecond},
					{net.ParseIP("45.90.28.0"), 6 * time.Millisecond},
					{net.ParseIP("45.90.28.0"), 10 * time.Millisecond},
				},
			},
			true},
		{"Success v6",
			"  2     4 ms     3 ms     3 ms  2a01:e00:2b:f836:af9c::ffff",
			Hop{
				Seq: 2,
				Info: []HopInfo{
					{net.ParseIP("2a01:e00:2b:f836:af9c::ffff"), 4 * time.Millisecond},
					{net.ParseIP("2a01:e00:2b:f836:af9c::ffff"), 3 * time.Millisecond},
					{net.ParseIP("2a01:e00:2b:f836:af9c::ffff"), 3 * time.Millisecond},
				},
			},
			true},
		{"Full Timeout v4",
			"3     *        *        *     Request timed out.",
			Hop{
				Seq: 3,
				Info: []HopInfo{
					{nil, -1},
					{nil, -1},
					{nil, -1},
				},
			},
			true},
		{"Partial Timeout v4",
			"  1     8 ms     *    10 ms  45.90.28.0",
			Hop{
				Seq: 1,
				Info: []HopInfo{
					{net.ParseIP("45.90.28.0"), 8 * time.Millisecond},
					{net.ParseIP("45.90.28.0"), -1},
					{net.ParseIP("45.90.28.0"), 10 * time.Millisecond},
				},
			},
			true},
		{"Partial Timeout v6",
			"  8     *        *       17 ms  2001:550:0:1000::8275:319a",
			Hop{
				Seq: 8,
				Info: []HopInfo{
					{net.ParseIP("2001:550:0:1000::8275:319a"), -1},
					{net.ParseIP("2001:550:0:1000::8275:319a"), -1},
					{net.ParseIP("2001:550:0:1000::8275:319a"), 17 * time.Millisecond},
				},
			},
			true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop, ok := parseTracertLine(tt.line)
			if !reflect.DeepEqual(hop, tt.hop) {
				t.Errorf("parseTracertLine() hop = %v, want %v", hop, tt.hop)
			}
			if ok != tt.ok {
				t.Errorf("parseTracertLine() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}
