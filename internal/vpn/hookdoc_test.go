package vpn

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestHookInputShape(t *testing.T) {
	b, _ := json.Marshal(HookInput{Version: 1, Trigger: Trigger, Instance: "headscale", Op: OpDevices, Ranges: []string{"100.64.0.0/10"}})
	if string(b) != `{"version":1,"trigger":"vpn","instance":"headscale","op":"devices","ranges":["100.64.0.0/10"]}` {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(HookInput{Version: 1, Trigger: Trigger, Instance: "headscale", Op: OpDNS, Records: []Record{{"a.example.org", "A", "100.64.0.1"}}})
	if string(b) != `{"version":1,"trigger":"vpn","instance":"headscale","op":"dns","records":[{"name":"a.example.org","type":"A","value":"100.64.0.1"}]}` {
		t.Fatal(string(b))
	}
}

func TestParseHookDevices(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	clock = func() time.Time { return now }
	defer func() { clock = time.Now }()
	ranges := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	doc := func(devs ...string) []byte {
		return []byte(`{"version":1,"gateway":"100.64.0.1","devices":[` + strings.Join(devs, ",") + `]}`)
	}
	dev := func(id, addr string, extra ...string) string {
		s := fmt.Sprintf(`{"id":%q,"name":"n%s","address":%q,"owner":"sub-%s","online":true,"last_seen":"2026-11-13T11:00:00Z","expires":null`, id, id, addr, id)
		for _, e := range extra {
			s += "," + e
		}
		return s + "}"
	}
	ok, err := ParseHookDevices(doc(dev("1", "100.64.0.7")), ranges)
	if err != nil || len(ok.Devices) != 1 || ok.Gateway.String() != "100.64.0.1" || ok.Devices[0].Owner != "sub-1" || !ok.Devices[0].Online {
		t.Fatalf("%+v %v", ok, err)
	}
	refusals := map[string][]byte{
		"5 MiB":           []byte(`{"version":1,"gateway":"100.64.0.1","devices":[],"pad":"` + strings.Repeat("x", 5<<20) + `"}`),
		"version 2":       []byte(`{"version":2,"gateway":"100.64.0.1","devices":[]}`),
		"unknown key":     []byte(`{"version":1,"gateway":"100.64.0.1","devices":[],"x":1}`),
		"unknown dev key": doc(dev("1", "100.64.0.7", `"tags":[]`)),
		"no gateway":      []byte(`{"version":1,"devices":[]}`),
		"gateway outside": []byte(`{"version":1,"gateway":"10.0.0.1","devices":[]}`),
		"gateway IPv6":    []byte(`{"version":1,"gateway":"fd7a::1","devices":[]}`),
		"not JSON":        []byte(`nope`),
		"trailing":        []byte(`{"version":1,"gateway":"100.64.0.1","devices":[]} {}`),
		"10 001 devices":  tooMany(),
	}
	for name, b := range refusals {
		if _, err := ParseHookDevices(b, ranges); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "sub-") || strings.Contains(err.Error(), "xxxx") {
			t.Errorf("%s: error quotes the document: %v", name, err)
		}
	}
	drops := []struct {
		name, dev, reason string
	}{
		{"ipv6", dev("6", "fd7a:115c:a1e0::7"), DropIPv6},
		{"outside", dev("o", "10.1.2.3"), DropOutside},
		{"expired", dev("e", "100.64.0.9", `"expires":"2026-11-13T11:59:59Z"`)[0:0] + `{"id":"e","name":"x","address":"100.64.0.9","owner":"o","online":false,"last_seen":null,"expires":"2026-11-13T11:59:59Z"}`, DropExpired},
		{"the gateway listed as a device is dropped", dev("g", "100.64.0.1"), DropGateway},
		{"bad address", dev("b", "nope"), DropInvalid},
		{"no owner", `{"id":"x","name":"x","address":"100.64.0.5","owner":"","online":false,"last_seen":null,"expires":null}`, DropInvalid},
	}
	for _, d := range drops {
		got, err := ParseHookDevices(doc(dev("1", "100.64.0.7"), d.dev), ranges)
		if err != nil || len(got.Devices) != 1 || len(got.Dropped) != 1 || got.Dropped[0].Reason != d.reason {
			t.Errorf("%s: %+v %v", d.name, got, err)
		}
	}
	// A duplicate address drops every device with it.
	got, err := ParseHookDevices(doc(dev("1", "100.64.0.7"), dev("2", "100.64.0.7"), dev("3", "100.64.0.8")), ranges)
	if err != nil || len(got.Devices) != 1 || got.Devices[0].ID != "3" || len(got.Dropped) != 2 || got.Dropped[0].Reason != DropDuplicate || got.Dropped[1].Reason != DropDuplicate {
		t.Fatalf("duplicate: %+v %v", got, err)
	}
}

func tooMany() []byte {
	var b strings.Builder
	b.WriteString(`{"version":1,"gateway":"100.64.0.1","devices":[`)
	for i := 0; i < MaxDevices+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"%d","name":"n","address":"100.65.%d.%d","owner":"o","online":false,"last_seen":null,"expires":null}`, i, i/250, i%250+1)
	}
	b.WriteString("]}")
	return []byte(b.String())
}
