package main

import (
	"errors"
	"net/netip"
	"testing"
)

func TestMetricsBindAddr(t *testing.T) {
	own := func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("172.18.0.5")}, nil
	}
	lookup := map[string][]string{"hub-metrics": {"172.18.0.5"}, "two": {"172.18.0.5", "172.18.0.6"}, "other": {"172.18.0.9"}, "none": {}}
	lk := func(h string) ([]netip.Addr, error) {
		ips, ok := lookup[h]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, s := range ips {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
	if got, err := metricsBindAddr("hub-metrics:9100", lk, own); err != nil || got != "172.18.0.5:9100" {
		t.Errorf("hub-metrics = %q, %v", got, err)
	}
	for _, bad := range []string{":9100", "0.0.0.0:9100", "[::]:9100", "127.0.0.1:9100", "two:9100", "other:9100", "none:9100", "missing:9100", "hub-metrics"} {
		if got, err := metricsBindAddr(bad, lk, own); err == nil {
			t.Errorf("%s accepted: %s", bad, got)
		}
	}
}
