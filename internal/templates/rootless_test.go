package templates

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// rootlessVector is one entry of testdata/rootless_vectors.json, a byte
// copy of portcullis-templates tests/rootless_vectors.json (its lint
// compares the two): compose, the manifest's ports (port = the host port),
// the instance env, the port start and the verdict.
type rootlessVector struct {
	Name    string `json:"name"`
	Compose string `json:"compose"`
	Ports   []struct {
		Key      string `json:"key"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
	Env       map[string]string `json:"env"`
	PortStart int               `json:"port_start"`
	Want      Compat            `json:"want"`
}

func TestRootlessVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/rootless_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []rootlessVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 11 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		var m Manifest
		for _, p := range v.Ports {
			m.Ports = append(m.Ports, Port{Key: p.Key, Container: p.Port, Default: p.Port, Protocol: p.Protocol})
		}
		got := RootlessCompat([]byte(v.Compose), m, v.Env, v.PortStart)
		if !reflect.DeepEqual(got, v.Want) {
			t.Errorf("%s:\n got %#v\nwant %#v", v.Name, got, v.Want)
		}
	}
}

// Rules the shared vectors don't cover.
func TestRootlessCompatRules(t *testing.T) {
	for _, c := range []struct {
		name    string
		compose string
		m       Manifest
		env     map[string]string
		want    Compat
	}{
		{"a non-device source is never shown", "services:\n  a:\n    image: x\n    devices:\n      - ${DEV:-/dev/null}:/dev/x\n", Manifest{}, map[string]string{"DEV": "/home/secret value"},
			Compat{CompatRefused, []string{"service a passes the host device a non-device source: device access needs host root"}}},
		{"empty env value takes the :- default", "services:\n  a:\n    image: x\n    devices:\n      - ${DEV:-/dev/null}:/dev/x\n", Manifest{}, map[string]string{"DEV": ""},
			Compat{CompatDegraded, []string{"service a has device slots: host devices can't be passed under rootless Podman"}}},
		{"SYS_ADMIN with CAP_ prefix", "services:\n  a:\n    image: x\n    cap_add: [cap_sys_admin]\n", Manifest{}, nil,
			Compat{CompatRefused, []string{"service a needs SYS_ADMIN (raw device access needs host root)"}}},
		{"group_add id", "services:\n  a:\n    image: x\n    group_add: [\"70001\", \"100\"]\n", Manifest{}, nil,
			Compat{CompatRefused, []string{"service a runs as id 70001, outside the rootless id range (0–65535)"}}},
		{"user from a variable", "services:\n  a:\n    image: x\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n", Manifest{}, map[string]string{"PUID": "100000"},
			Compat{CompatRefused, []string{"service a runs as id 100000, outside the rootless id range (0–65535)"}}},
		{"instance port override", "services:\n  a:\n    image: x\n", Manifest{Ports: []Port{{Key: "P", Default: 8080}}}, map[string]string{"P": "53"},
			Compat{CompatRefused, []string{"host port 53/tcp is below net.ipv4.ip_unprivileged_port_start (80): lower it to 53 on the host to allow it (any local user can then bind ports from 53)"}}},
		{"range start", "services:\n  a:\n    image: x\n", Manifest{Ports: []Port{{Key: "R", Range: "49152-65535", Protocol: "udp"}}}, nil,
			Compat{CompatDegraded, []string{"UDP clients on port 49152 appear with a rewritten source address"}}},
		{"folder runs_as", "services:\n  a:\n    image: x\n", Manifest{Settings: &SettingsSpec{Options: []Option{{Key: "media", Target: &SettingTarget{Service: "a"}, Folder: &FolderSpec{RunsAs: &RunsAs{UID: intp(70000)}}}}}}, nil,
			Compat{CompatRefused, []string{"service a runs as id 70000, outside the rootless id range (0–65535)"}}},
		{"refused hides degraded", "services:\n  a:\n    image: x\n    network_mode: host\n    cap_add: [SYS_RAWIO]\n", Manifest{}, nil,
			Compat{CompatRefused, []string{"service a needs SYS_RAWIO (raw device access needs host root)"}}},
		{"unreadable compose", "services: [", Manifest{}, nil, Compat{CompatRefused, nil}},
	} {
		got := RootlessCompat([]byte(c.compose), c.m, c.env, 80)
		if c.name == "unreadable compose" {
			if got.Status != CompatRefused || len(got.Reasons) != 1 {
				t.Errorf("%s: %#v", c.name, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %#v\nwant %#v", c.name, got, c.want)
		}
	}
}

func intp(n int) *int { return &n }
