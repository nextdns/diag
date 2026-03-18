//go:build windows
// +build windows

package traceroute

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	modIPHLPAPI         = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = modIPHLPAPI.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = modIPHLPAPI.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = modIPHLPAPI.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = modIPHLPAPI.NewProc("IcmpSendEcho2Ex")
	procIcmp6SendEcho2  = modIPHLPAPI.NewProc("Icmp6SendEcho2")
)

type windowsTracer struct {
	family  int
	handle  syscall.Handle
	request []byte
}

type ipOptionInformation32 struct {
	TTL         byte
	TOS         byte
	Flags       byte
	OptionsSize byte
	OptionsData uint32
}

func (t *Tracer) Trace(ctx context.Context, dest net.IP, c chan Hop) error {
	cfg := t.traceConfig(dest)

	wt, err := newWindowsTracer(cfg.family, cfg.packetSize)
	if err != nil {
		return err
	}
	defer wt.Close()

	return t.traceWithFunc(ctx, cfg, c, func(ttl int, timeout time.Duration) (HopInfo, bool, error) {
		return wt.probe(ctx, ttl, dest, timeout)
	})
}

func newWindowsTracer(family int, packetSize int) (*windowsTracer, error) {
	var (
		handle syscall.Handle
		err    error
	)
	switch family {
	case 4:
		handle, err = icmpCreateFile()
	case 6:
		handle, err = icmp6CreateFile()
	default:
		return nil, fmt.Errorf("unsupported family %d", family)
	}
	if err != nil {
		return nil, err
	}
	return &windowsTracer{
		family:  family,
		handle:  handle,
		request: make([]byte, packetSize),
	}, nil
}

func (t *windowsTracer) Close() error {
	if t.handle == 0 {
		return nil
	}
	err := icmpCloseHandle(t.handle)
	t.handle = 0
	return err
}

func (t *windowsTracer) probe(ctx context.Context, ttl int, dest net.IP, hopTimeout time.Duration) (HopInfo, bool, error) {
	timeout, err := probeTimeout(ctx, hopTimeout)
	if err != nil {
		return HopInfo{}, false, err
	}
	opts := ipOptionInformation32{TTL: byte(ttl)}
	switch t.family {
	case 4:
		reply, err := t.probeIPv4(dest, opts, timeout)
		if err != nil {
			return HopInfo{}, false, err
		}
		return parseWindowsIPv4Reply(reply)
	case 6:
		reply, err := t.probeIPv6(dest, opts, timeout)
		if err != nil {
			return HopInfo{}, false, err
		}
		return parseWindowsIPv6Reply(reply)
	default:
		return HopInfo{}, false, fmt.Errorf("unsupported family %d", t.family)
	}
}

func (t *windowsTracer) probeIPv4(dest net.IP, opts ipOptionInformation32, timeout time.Duration) ([]byte, error) {
	ip4 := dest.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid IPv4 destination %v", dest)
	}
	reply := make([]byte, windowsIPv4ReplyPrefixSize+len(t.request)+64)
	r1, _, e1 := procIcmpSendEcho2Ex.Call(
		uintptr(t.handle),
		0,
		0,
		0,
		0,
		uintptr(ipv4Address(ip4)),
		bytesPtr(t.request),
		uintptr(len(t.request)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeoutMilliseconds(timeout)),
	)
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno == windowsIPReqTimedOut {
			return timeoutWindowsIPv4Reply(), nil
		}
		if e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("IcmpSendEcho2Ex: %w", e1)
		}
		return nil, fmt.Errorf("IcmpSendEcho2Ex: no replies")
	}
	return reply, nil
}

func (t *windowsTracer) probeIPv6(dest net.IP, opts ipOptionInformation32, timeout time.Duration) ([]byte, error) {
	ip6 := dest.To16()
	if ip6 == nil || dest.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 destination %v", dest)
	}
	src := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	dst := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	copy(dst.Addr[:], ip6)
	reply := make([]byte, windowsIPv6ReplyPrefixSize+len(t.request)+128)
	r1, _, e1 := procIcmp6SendEcho2.Call(
		uintptr(t.handle),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&dst)),
		bytesPtr(t.request),
		uintptr(len(t.request)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeoutMilliseconds(timeout)),
	)
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno == windowsIPReqTimedOut {
			return timeoutWindowsIPv6Reply(), nil
		}
		if e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("Icmp6SendEcho2: %w", e1)
		}
		return nil, fmt.Errorf("Icmp6SendEcho2: no replies")
	}
	return reply, nil
}

func icmpCreateFile() (syscall.Handle, error) {
	r1, _, e1 := procIcmpCreateFile.Call()
	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		if e1 != syscall.Errno(0) {
			return 0, fmt.Errorf("IcmpCreateFile: %w", e1)
		}
		return 0, fmt.Errorf("IcmpCreateFile: invalid handle")
	}
	return handle, nil
}

func icmp6CreateFile() (syscall.Handle, error) {
	r1, _, e1 := procIcmp6CreateFile.Call()
	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		if e1 != syscall.Errno(0) {
			return 0, fmt.Errorf("Icmp6CreateFile: %w", e1)
		}
		return 0, fmt.Errorf("Icmp6CreateFile: invalid handle")
	}
	return handle, nil
}

func icmpCloseHandle(handle syscall.Handle) error {
	r1, _, e1 := procIcmpCloseHandle.Call(uintptr(handle))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return fmt.Errorf("IcmpCloseHandle: %w", e1)
		}
		return fmt.Errorf("IcmpCloseHandle: call failed")
	}
	return nil
}

func probeTimeout(ctx context.Context, timeout time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		timeout = time.Millisecond
	}
	return timeout, nil
}

func timeoutMilliseconds(timeout time.Duration) uint32 {
	if timeout <= 0 {
		return 1
	}
	ms := timeout / time.Millisecond
	if timeout%time.Millisecond != 0 {
		ms++
	}
	if ms == 0 {
		ms = 1
	}
	return uint32(ms)
}

func bytesPtr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func ipv4Address(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

func timeoutWindowsIPv4Reply() []byte {
	reply := make([]byte, windowsIPv4ReplyPrefixSize)
	binary.LittleEndian.PutUint32(reply[4:8], windowsIPReqTimedOut)
	return reply
}

func timeoutWindowsIPv6Reply() []byte {
	reply := make([]byte, windowsIPv6ReplyPrefixSize)
	binary.LittleEndian.PutUint32(reply[windowsIPv6StatusOffset:windowsIPv6StatusOffset+4], windowsIPReqTimedOut)
	return reply
}
