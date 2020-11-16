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
