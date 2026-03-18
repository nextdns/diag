package traceback

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/nextdns/diag/traceroute"
)

type hop struct {
	Seq    int     `json:"seq"`
	Probes []probe `json:"probes,omitempty"`
}

type probe struct {
	IP    string `json:"ip,omitempty"`
	RTTMs int64  `json:"rtt_ms"`
}

func Fetch(cl *http.Client, url string) ([]traceroute.Hop, error) {
	res, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Hops     []hop  `json:"hops,omitempty"`
		Complete bool   `json:"complete"`
		Error    string `json:"error,omitempty"`
	}
	if trimmed := bytes.TrimSpace(b); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &resp); err != nil {
			if res.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("status %d: %s", res.StatusCode, string(trimmed))
			}
			return nil, err
		}
	}
	switch {
	case resp.Error != "":
		return makeHops(resp.Hops), fmt.Errorf("%s", resp.Error)
	case res.StatusCode != http.StatusOK:
		return makeHops(resp.Hops), fmt.Errorf("status %d", res.StatusCode)
	case !resp.Complete:
		return makeHops(resp.Hops), fmt.Errorf("traceback incomplete")
	}
	return makeHops(resp.Hops), nil
}

func makeHops(raw []hop) []traceroute.Hop {
	hops := make([]traceroute.Hop, 0, len(raw))
	for _, h := range raw {
		info := make([]traceroute.HopInfo, 0, len(h.Probes))
		for _, probe := range h.Probes {
			var rtt time.Duration
			if probe.RTTMs < 0 {
				rtt = -1
			} else {
				rtt = time.Duration(probe.RTTMs) * time.Millisecond
			}
			info = append(info, traceroute.HopInfo{
				IP:  net.ParseIP(probe.IP),
				RTT: rtt,
			})
		}
		hops = append(hops, traceroute.Hop{
			Seq:  h.Seq,
			Info: info,
		})
	}
	return hops
}
