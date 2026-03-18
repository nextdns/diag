package traceroute

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParseWindowsIPv4Reply(t *testing.T) {
	reply := make([]byte, windowsIPv4ReplyPrefixSize)
	copy(reply[:4], []byte{45, 90, 28, 0})
	binary.LittleEndian.PutUint32(reply[4:8], windowsIPTTLExpiredTransit)
	binary.LittleEndian.PutUint32(reply[8:12], 17)

	info, last, err := parseWindowsIPv4Reply(reply)
	if err != nil {
		t.Fatalf("parseWindowsIPv4Reply() error = %v", err)
	}
	if got, want := info, (HopInfo{
		IP:  net.IPv4(45, 90, 28, 0),
		RTT: 17 * time.Millisecond,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsIPv4Reply() info = %#v, want %#v", got, want)
	}
	if last {
		t.Fatal("parseWindowsIPv4Reply() last = true, want false")
	}
}

func TestParseWindowsIPv4ReplyTimeout(t *testing.T) {
	reply := make([]byte, windowsIPv4ReplyPrefixSize)
	binary.LittleEndian.PutUint32(reply[4:8], windowsIPReqTimedOut)

	info, last, err := parseWindowsIPv4Reply(reply)
	if err != nil {
		t.Fatalf("parseWindowsIPv4Reply() error = %v", err)
	}
	if got, want := info, (HopInfo{RTT: -1}); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsIPv4Reply() info = %#v, want %#v", got, want)
	}
	if last {
		t.Fatal("parseWindowsIPv4Reply() last = true, want false")
	}
}

func TestParseWindowsIPv6Reply(t *testing.T) {
	reply := make([]byte, windowsIPv6ReplyPrefixSize)
	ip := net.ParseIP("2001:db8::5").To16()
	copy(reply[windowsIPv6AddressOffset:windowsIPv6AddressOffset+net.IPv6len], ip)
	binary.LittleEndian.PutUint32(reply[windowsIPv6StatusOffset:windowsIPv6StatusOffset+4], windowsIPSuccess)
	binary.LittleEndian.PutUint32(reply[windowsIPv6RTTOffset:windowsIPv6RTTOffset+4], 9)

	info, last, err := parseWindowsIPv6Reply(reply)
	if err != nil {
		t.Fatalf("parseWindowsIPv6Reply() error = %v", err)
	}
	if got, want := info, (HopInfo{
		IP:  ip,
		RTT: 9 * time.Millisecond,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsIPv6Reply() info = %#v, want %#v", got, want)
	}
	if !last {
		t.Fatal("parseWindowsIPv6Reply() last = false, want true")
	}
}

func TestParseWindowsIPv6ReplyTimeout(t *testing.T) {
	reply := make([]byte, windowsIPv6ReplyPrefixSize)
	binary.LittleEndian.PutUint32(reply[windowsIPv6StatusOffset:windowsIPv6StatusOffset+4], windowsIPReqTimedOut)

	info, last, err := parseWindowsIPv6Reply(reply)
	if err != nil {
		t.Fatalf("parseWindowsIPv6Reply() error = %v", err)
	}
	if got, want := info, (HopInfo{RTT: -1}); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsIPv6Reply() info = %#v, want %#v", got, want)
	}
	if last {
		t.Fatal("parseWindowsIPv6Reply() last = true, want false")
	}
}
