package traceroute

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func parseTracertLine(line string) (Hop, bool) {
	var seq, rtt1, rtt2, rtt3 int
	var ip string
	line = strings.ReplaceAll(line, "*", "-1 ms")
	_, err := fmt.Sscanf(line, "%d %d ms %d ms %d ms %s", &seq, &rtt1, &rtt2, &rtt3, &ip)
	if err != nil {
		return Hop{}, false
	}
	nip := net.ParseIP(ip)
	return Hop{
		Seq: seq,
		Info: []HopInfo{
			{nip, tracerMsToDuration(rtt1)},
			{nip, tracerMsToDuration(rtt2)},
			{nip, tracerMsToDuration(rtt3)},
		},
	}, true
}

func tracerMsToDuration(ms int) time.Duration {
	if ms == -1 {
		return -1
	}
	return time.Duration(ms) * time.Millisecond
}
