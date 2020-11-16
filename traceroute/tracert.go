package traceroute

import (
	"fmt"
	"net"
	"time"
)

func parseTracertLine(line string) (Hop, bool) {
	var seq, rtt1, rtt2, rtt3 int
	var ip string
	_, err := fmt.Sscanf(line, "%d %d ms %d ms %d ms %s", &seq, &rtt1, &rtt2, &rtt3, &ip)
	if err != nil {
		return Hop{}, false
	}
	nip := net.ParseIP(ip)
	if nip == nil {
		return Hop{}, false
	}
	return Hop{
		Seq: seq,
		Info: []HopInfo{
			{nip, time.Duration(rtt1) * time.Millisecond},
			{nip, time.Duration(rtt2) * time.Millisecond},
			{nip, time.Duration(rtt3) * time.Millisecond},
		},
	}, true
}
