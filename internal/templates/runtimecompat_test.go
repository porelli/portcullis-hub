package templates

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// runtimeVector is one entry of testdata/runtime_vectors.json, a byte
// copy of portcullis-templates tests/runtime_vectors.json (its lint
// compares the two): the runtime, compose, the manifest's ports (port =
// the host port, service its compose service), the instance env, setting
// values (option key → value; the option is declared), the port start
// and the verdict.
type runtimeVector struct {
	Name    string       `json:"name"`
	Runtime runtime.Kind `json:"runtime"`
	Compose string       `json:"compose"`
	Ports   []struct {
		Key      string `json:"key"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	} `json:"ports"`
	Env       map[string]string `json:"env"`
	Settings  map[string]string `json:"settings"`
	PortStart int               `json:"port_start"`
	Want      Compat            `json:"want"`
}

func loadRuntimeVectors(t *testing.T) []runtimeVector {
	t.Helper()
	b, err := os.ReadFile("testdata/runtime_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []runtimeVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

// vectorVerdict is v's verdict through RuntimeCompat.
func vectorVerdict(v runtimeVector) Compat {
	var m Manifest
	for _, p := range v.Ports {
		m.Ports = append(m.Ports, Port{Key: p.Key, Container: p.Port, Default: p.Port, Protocol: p.Protocol, Service: p.Service})
	}
	env := map[string]string{}
	for k, val := range v.Env {
		env[k] = val
	}
	if len(v.Settings) > 0 {
		m.Settings = &SettingsSpec{}
		for k, val := range v.Settings {
			m.Settings.Options = append(m.Settings.Options, Option{Key: k, Type: "path"})
			env[k] = val
		}
	}
	return RuntimeCompat(v.Runtime, []byte(v.Compose), m, env, v.PortStart)
}

func checkVectors(t *testing.T, rt runtime.Kind, min int) {
	n := 0
	for _, v := range loadRuntimeVectors(t) {
		if v.Runtime != rt {
			continue
		}
		n++
		got := vectorVerdict(v)
		if got.Runtime != rt || got.Status != v.Want.Status || !reflect.DeepEqual(got.Reasons, v.Want.Reasons) {
			t.Errorf("%s:\n got %#v\nwant %#v", v.Name, got, v.Want)
		}
	}
	if n < min {
		t.Fatalf("%d %s vectors", n, rt)
	}
}

func TestRootlessVectors(t *testing.T) { checkVectors(t, runtime.KindPodman, 11) }

// TestRuntimeCompatKubernetes: the Kubernetes table (contract §3.4) on
// the shared vectors.
func TestRuntimeCompatKubernetes(t *testing.T) { checkVectors(t, runtime.KindKubernetes, 15) }

func TestRuntimeCompatDockerAlwaysOK(t *testing.T) {
	for _, v := range loadRuntimeVectors(t) {
		v.Runtime = runtime.KindDocker
		if got := vectorVerdict(v); got.Status != CompatOK || len(got.Reasons) != 0 || got.Runtime != runtime.KindDocker {
			t.Errorf("%s under docker: %#v", v.Name, got)
		}
	}
}

func TestRuntimeVectorsNameRuntimes(t *testing.T) {
	for _, v := range loadRuntimeVectors(t) {
		if v.Runtime != runtime.KindPodman && v.Runtime != runtime.KindKubernetes {
			t.Errorf("%s: runtime %q", v.Name, v.Runtime)
		}
	}
}

// The Hub passes its bind roots under EnvBindRoots.
func TestKubeCompatBindRootsFromEnv(t *testing.T) {
	compose := []byte("services:\n  a:\n    image: x\n    volumes:\n      - /data/photos:/photos\n")
	if got := RuntimeCompat(runtime.KindKubernetes, compose, Manifest{}, nil, 80); got.Status != CompatRefused {
		t.Errorf("default roots: %#v", got)
	}
	if got := RuntimeCompat(runtime.KindKubernetes, compose, Manifest{}, map[string]string{EnvBindRoots: "/data:/srv"}, 80); got.Status != CompatOK {
		t.Errorf("roots /data: %#v", got)
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
			Compat{"", CompatRefused, []string{"service a passes the host device a non-device source: device access needs host root"}}},
		{"empty env value takes the :- default", "services:\n  a:\n    image: x\n    devices:\n      - ${DEV:-/dev/null}:/dev/x\n", Manifest{}, map[string]string{"DEV": ""},
			Compat{"", CompatDegraded, []string{"service a has device slots: host devices can't be passed under rootless Podman"}}},
		{"SYS_ADMIN with CAP_ prefix", "services:\n  a:\n    image: x\n    cap_add: [cap_sys_admin]\n", Manifest{}, nil,
			Compat{"", CompatRefused, []string{"service a needs SYS_ADMIN (raw device access needs host root)"}}},
		{"group_add id", "services:\n  a:\n    image: x\n    group_add: [\"70001\", \"100\"]\n", Manifest{}, nil,
			Compat{"", CompatRefused, []string{"service a runs as id 70001, outside the rootless id range (0–65535)"}}},
		{"user from a variable", "services:\n  a:\n    image: x\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n", Manifest{}, map[string]string{"PUID": "100000"},
			Compat{"", CompatRefused, []string{"service a runs as id 100000, outside the rootless id range (0–65535)"}}},
		{"instance port override", "services:\n  a:\n    image: x\n", Manifest{Ports: []Port{{Key: "P", Default: 8080}}}, map[string]string{"P": "53"},
			Compat{"", CompatRefused, []string{"host port 53/tcp is below net.ipv4.ip_unprivileged_port_start (80): lower it to 53 on the host to allow it (any local user can then bind ports from 53)"}}},
		{"range start", "services:\n  a:\n    image: x\n", Manifest{Ports: []Port{{Key: "R", Range: "49152-65535", Protocol: "udp"}}}, nil,
			Compat{"", CompatDegraded, []string{"UDP clients on port 49152 appear with a rewritten source address"}}},
		{"folder runs_as", "services:\n  a:\n    image: x\n", Manifest{Settings: &SettingsSpec{Options: []Option{{Key: "media", Target: &SettingTarget{Service: "a"}, Folder: &FolderSpec{RunsAs: &RunsAs{UID: intp(70000)}}}}}}, nil,
			Compat{"", CompatRefused, []string{"service a runs as id 70000, outside the rootless id range (0–65535)"}}},
		{"refused hides degraded", "services:\n  a:\n    image: x\n    network_mode: host\n    cap_add: [SYS_RAWIO]\n", Manifest{}, nil,
			Compat{"", CompatRefused, []string{"service a needs SYS_RAWIO (raw device access needs host root)"}}},
		{"network_mode from a variable", "services:\n  a:\n    image: x\n    network_mode: ${NM:-host}\n", Manifest{}, nil,
			Compat{"", CompatDegraded, []string{"host networking: published ports must stay at or above 80"}}},
		{"unreadable compose", "services: [", Manifest{}, nil, Compat{"", CompatRefused, nil}},
	} {
		got := RuntimeCompat(runtime.KindPodman, []byte(c.compose), c.m, c.env, 80)
		got.Runtime = ""
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
