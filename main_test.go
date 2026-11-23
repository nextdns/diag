package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeResolversSplitsCombinedAddresses(t *testing.T) {
	got := normalizeResolvers([]string{
		"45.90.28.219 45.90.30.219",
		"45.90.28.219",
		"not-an-ip",
		"2a07:a8c0::",
		" 1.1.1.1,8.8.8.8 ",
		"",
	})
	want := []string{
		"45.90.28.219",
		"45.90.30.219",
		"2a07:a8c0::",
		"1.1.1.1",
		"8.8.8.8",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeResolvers() = %#v, want %#v", got, want)
	}
}

func TestNormalizeResolversDropsUnusableInput(t *testing.T) {
	if got := normalizeResolvers([]string{"45.90.28.219 45.90.30.219"}); len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
	if got := normalizeResolvers(nil); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if got := normalizeResolvers([]string{"dns.nextdns.io"}); len(got) != 0 {
		t.Fatalf("got %#v, want no addresses", got)
	}
}

func TestFixedDNSDialUsesLiteralAndIgnoresRequestedName(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	// The requested address is the malformed resolver string from the report.
	// Dialing it would fail with "no such host" instead of reaching the listener.
	dial := dnsDial([]string{"127.0.0.1"}, port, false)
	conn, err := dial(context.Background(), "udp", "45.90.28.219 45.90.30.219:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("packet = %q", buf[:n])
	}
}

func TestFixedDNSDialRejectsNonLiteralServer(t *testing.T) {
	dial := dnsDial([]string{"45.90.28.219 45.90.30.219"}, "53", false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := dial(ctx, "udp", "127.0.0.1:53")
	if err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("non-literal resolver dial took %s", time.Since(start))
	}
}

func TestRotatingDNSDialCyclesServers(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(probe.LocalAddr().String())
	probe.Close()
	if err != nil {
		t.Fatal(err)
	}
	a, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	dial := dnsDial([]string{"127.0.0.1", "127.0.0.2"}, port, true)
	for i, pc := range []net.PacketConn{a, b, a} {
		conn, err := dial(context.Background(), "udp", "192.0.2.1:53")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		buf := make([]byte, 1)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("server %d: %v", i, err)
		}
		if n != 1 || buf[0] != byte(i) {
			t.Fatalf("server %d packet = %v", i, buf[:n])
		}
	}
}

func TestShouldRetryPost(t *testing.T) {
	wrapped := &net.OpError{
		Op:  "dial",
		Net: "udp",
		Err: &net.DNSError{
			Err:        "no such host",
			Name:       "45.90.28.219 45.90.30.219",
			IsNotFound: true,
		},
	}
	if !shouldRetryPost(wrapped) {
		t.Fatal("wrapped DNS error should be retried")
	}
	if !shouldRetryPost(&net.DNSError{Err: "i/o timeout", Name: "api.nextdns.io", IsTimeout: true}) {
		t.Fatal("timeout DNS error should be retried")
	}
	if shouldRetryPost(&postStatusError{code: http.StatusBadGateway}) {
		t.Fatal("HTTP status must not be retried")
	}
	if shouldRetryPost(nil) {
		t.Fatal("nil error must not be retried")
	}
	if shouldRetryPost(errors.New("decode failed")) {
		t.Fatal("unrelated error must not be retried")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPostWithClientsFallsBackOnDNSError(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"abc123"}`))
	}))
	defer srv.Close()

	failed := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Err: "i/o timeout", Name: "api.nextdns.io", IsTimeout: true}
	})}
	id, err := postWithClients([]byte(`{"HasV6":false}`), srv.URL, []*http.Client{failed, srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc123" {
		t.Fatalf("id = %q", id)
	}
	if calls != 1 {
		t.Fatalf("server calls = %d, want 1", calls)
	}
}

func TestPostWithClientsDoesNotRetryHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	second := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("fallback client was used")
		return nil, errors.New("unused")
	})}
	_, err := postWithClients([]byte(`{}`), srv.URL, []*http.Client{srv.Client(), second})
	var status *postStatusError
	if !errors.As(err, &status) || status.code != http.StatusInternalServerError {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(status.body, "nope") {
		t.Fatalf("body = %q", status.body)
	}
}

func TestPostWithClientsReportsBothFailures(t *testing.T) {
	fail := func(msg string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: msg, Name: "api.nextdns.io", IsTimeout: true}
		})}
	}
	_, err := postWithClients([]byte(`{}`), "https://api.nextdns.io/diagnostic", []*http.Client{
		fail("i/o timeout"),
		fail("network is unreachable"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "i/o timeout") || !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("error = %v", err)
	}
}
