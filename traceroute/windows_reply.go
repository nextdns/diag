package traceroute

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	windowsIPSuccess           = 0
	windowsIPReqTimedOut       = 11010
	windowsIPTTLExpiredTransit = 11013
	windowsIPTTLExpiredReassem = 11014

	windowsIPv4ReplyPrefixSize = 28
	windowsIPv6ReplyPrefixSize = 36

	windowsIPv6AddressOffset = 8
	windowsIPv6StatusOffset  = 28
	windowsIPv6RTTOffset     = 32
)

func parseWindowsIPv4Reply(reply []byte) (HopInfo, bool, error) {
	if len(reply) < windowsIPv4ReplyPrefixSize {
		return HopInfo{}, false, fmt.Errorf("short ICMP reply buffer: got %d bytes", len(reply))
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	if status == windowsIPReqTimedOut {
		return HopInfo{RTT: -1}, false, nil
	}
	return HopInfo{
		IP:  net.IPv4(reply[0], reply[1], reply[2], reply[3]),
		RTT: time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond,
	}, !windowsTTLExpired(status), nil
}

func parseWindowsIPv6Reply(reply []byte) (HopInfo, bool, error) {
	if len(reply) < windowsIPv6ReplyPrefixSize {
		return HopInfo{}, false, fmt.Errorf("short ICMPv6 reply buffer: got %d bytes", len(reply))
	}
	status := binary.LittleEndian.Uint32(reply[windowsIPv6StatusOffset : windowsIPv6StatusOffset+4])
	if status == windowsIPReqTimedOut {
		return HopInfo{RTT: -1}, false, nil
	}
	ip := append(net.IP(nil), reply[windowsIPv6AddressOffset:windowsIPv6AddressOffset+net.IPv6len]...)
	return HopInfo{
		IP:  ip,
		RTT: time.Duration(binary.LittleEndian.Uint32(reply[windowsIPv6RTTOffset:windowsIPv6RTTOffset+4])) * time.Millisecond,
	}, !windowsTTLExpired(status), nil
}

func windowsTTLExpired(status uint32) bool {
	return status == windowsIPTTLExpiredTransit || status == windowsIPTTLExpiredReassem
}
