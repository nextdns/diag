package traceback

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nextdns/diag/traceroute"
)

func TestFetchSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"remote_addr":"203.0.113.9:12345",
			"ip":"203.0.113.9",
			"hops":[
				{"seq":1,"probes":[{"ip":"10.0.0.1","rtt_ms":12},{"rtt_ms":-1},{"ip":"10.0.0.1","rtt_ms":15}]},
				{"seq":2,"probes":[{"ip":"203.0.113.9","rtt_ms":22}]}
			],
			"complete":true
		}`))
	}))
	defer srv.Close()

	hops, err := Fetch(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got, want := len(hops), 2; got != want {
		t.Fatalf("len(Hops) = %d, want %d", got, want)
	}
	if got, want := hops[0].Info[0].RTT, 12*time.Millisecond; got != want {
		t.Fatalf("Hops[0].Info[0].RTT = %s, want %s", got, want)
	}
	if got, want := hops[0].Info[0].IP.String(), "10.0.0.1"; got != want {
		t.Fatalf("Hops[0].Info[0].IP = %q, want %q", got, want)
	}
	if got, want := hops[0].Info[1].RTT, time.Duration(-1); got != want {
		t.Fatalf("Hops[0].Info[1].RTT = %s, want %s", got, want)
	}
}

func TestFetchErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte(`{
			"remote_addr":"203.0.113.9:12345",
			"ip":"203.0.113.9",
			"hops":[{"seq":1,"probes":[{"ip":"10.0.0.1","rtt_ms":9}]}],
			"complete":false,
			"error":"context deadline exceeded"
		}`))
	}))
	defer srv.Close()

	hops, err := Fetch(srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("Fetch() error = nil, want non-nil")
	}
	if got, want := err.Error(), "context deadline exceeded"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if got, want := len(hops), 1; got != want {
		t.Fatalf("len(Hops) = %d, want %d", got, want)
	}
}

func TestHopString(t *testing.T) {
	hop := traceroute.Hop{
		Seq: 1,
		Info: []traceroute.HopInfo{
			{IP: parseIP(t, "10.0.0.1"), RTT: 12 * time.Millisecond},
			{RTT: -1},
			{IP: parseIP(t, "10.0.0.1"), RTT: 15 * time.Millisecond},
		},
	}

	if got, want := hop.String(), "  1       10.0.0.1   12ms   *    15ms"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func parseIP(t *testing.T, s string) (ip net.IP) {
	t.Helper()
	ip = net.ParseIP(s)
	if ip == nil {
		t.Fatalf("ParseIP(%q) = nil", s)
	}
	return ip
}
