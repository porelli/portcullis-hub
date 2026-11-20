package nminus1

import (
	"os"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// The snapshot of contract §20.2 (nodeadm GET /v1/cluster; Task 8 makes it
// nodeadm.Snapshot, the same JSON).
type resources struct {
	CPUm     int64 `json:"cpu_m"`
	MemBytes int64 `json:"mem_bytes"`
}

type taint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Effect string `json:"effect"`
}

type toleration struct {
	Key      string                     `json:"key"`
	Operator string                     `json:"operator"`
	Value    string                     `json:"value"`
	Effect   string                     `json:"effect"`
	Seconds  jsonstrict.Nullable[int64] `json:"seconds"`
}

type expression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type snapNode struct {
	Name          string                         `json:"name"`
	Role          string                         `json:"role"`
	Ready         bool                           `json:"ready"`
	NotReadySince jsonstrict.Nullable[time.Time] `json:"not_ready_since"`
	Unschedulable bool                           `json:"unschedulable"`
	Allocatable   resources                      `json:"allocatable"`
	Labels        map[string]string              `json:"labels"`
	Taints        []taint                        `json:"taints"`
	Addresses     struct {
		Mesh   string   `json:"mesh"`
		LAN    []string `json:"lan"`
		Public []string `json:"public"`
	} `json:"addresses"`
	TraefikReady bool `json:"traefik_ready"`
	FencingReady bool `json:"fencing_ready"`
	EtcdMember   bool `json:"etcd_member"`
}

type enrolling struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Class  string `json:"class"`
	Site   string `json:"site"`
	MeshIP string `json:"mesh_ip"`
	Mesh   struct {
		Pub    string                      `json:"pub"`
		LAN    jsonstrict.Nullable[string] `json:"lan"`
		Public jsonstrict.Nullable[string] `json:"public"`
	} `json:"mesh"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

type podSet struct {
	Name string `json:"name"`
	Min  int    `json:"min"`
}

type snapPod struct {
	Name             string                      `json:"name"`
	Namespace        string                      `json:"namespace"`
	Node             string                      `json:"node"`
	Priority         int                         `json:"priority"`
	PriorityClass    string                      `json:"priority_class"`
	PreemptionPolicy string                      `json:"preemption_policy"`
	Requests         resources                   `json:"requests"`
	Tolerations      []toleration                `json:"tolerations"`
	RequiredAffinity [][]expression              `json:"required_affinity"`
	AntiAffinityHost bool                        `json:"anti_affinity_host"`
	SpreadHost       bool                        `json:"spread_host"`
	DaemonSet        bool                        `json:"daemonset"`
	Set              jsonstrict.Nullable[podSet] `json:"set"`
}

type voters struct {
	Voters  int `json:"voters"`
	Healthy int `json:"healthy"`
}

type snapshot struct {
	V         int         `json:"v"`
	TakenAt   time.Time   `json:"taken_at"`
	Nodes     []snapNode  `json:"nodes"`
	Enrolling []enrolling `json:"enrolling"`
	Pods      []snapPod   `json:"pods"`
	Quorum    struct {
		Etcd     voters `json:"etcd"`
		Vault    voters `json:"vault"`
		Sentinel voters `json:"sentinel"`
	} `json:"quorum"`
	Postgres struct {
		Instances    int                         `json:"instances"`
		SyncStandbys int                         `json:"sync_standbys"`
		Primary      jsonstrict.Nullable[string] `json:"primary"`
	} `json:"postgres"`
	Volumes []struct {
		Name          string                         `json:"name"`
		Robustness    string                         `json:"robustness"`
		DegradedSince jsonstrict.Nullable[time.Time] `json:"degraded_since"`
	} `json:"volumes"`
	Errors []string `json:"errors"`
}

type nminus1Vector struct {
	Name     string   `json:"name"`
	Snapshot snapshot `json:"snapshot"`
	Want     []struct {
		Node     string   `json:"node"`
		Level    string   `json:"level"`
		Unplaced []string `json:"unplaced"`
		Evicted  []string `json:"evicted"`
	} `json:"want"`
}

// shownName is how the results name a pod.
func shownName(p snapPod) string {
	if p.Namespace == "portcullis" {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

// TestNMinus1VectorsShape: nminus1_vectors.json (contract §20.7) decodes
// strictly; each case wants one result per snapshot node, the levels are
// green / yellow / red, and every pod named exists in the snapshot (named
// bare in the core namespace, else "<namespace>/<name>", Task 12 review M3).
func TestNMinus1VectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/nminus1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []nminus1Vector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 21 {
		t.Fatalf("%d vectors, want ≥ 21 (12 + the degraded-set cases of P7 + the unplaceable high pod)", len(vs))
	}
	levels := map[string]int{}
	highYellow := false
	for _, v := range vs {
		if v.Snapshot.V != 1 {
			t.Errorf("%s: snapshot v %d", v.Name, v.Snapshot.V)
		}
		nodes, pods := map[string]bool{}, map[string]bool{}
		for _, n := range v.Snapshot.Nodes {
			nodes[n.Name] = true
		}
		for _, p := range v.Snapshot.Pods {
			if !nodes[p.Node] || pods[shownName(p)] {
				t.Errorf("%s: pod %s on unknown node %s or repeated", v.Name, p.Name, p.Node)
			}
			pods[shownName(p)] = true
		}
		if len(v.Want) != len(v.Snapshot.Nodes) {
			t.Errorf("%s: %d results for %d nodes", v.Name, len(v.Want), len(v.Snapshot.Nodes))
		}
		for _, w := range v.Want {
			if !nodes[w.Node] {
				t.Errorf("%s: result for unknown node %s", v.Name, w.Node)
			}
			switch w.Level {
			case "green", "yellow", "red":
				levels[w.Level]++
			default:
				t.Errorf("%s: level %q", v.Name, w.Level)
			}
			for _, u := range w.Unplaced {
				for _, p := range v.Snapshot.Pods {
					highYellow = highYellow || (shownName(p) == u && p.PriorityClass == "portcullis-high" && w.Level == "yellow")
				}
			}
			for _, p := range append(append([]string{}, w.Unplaced...), w.Evicted...) {
				if !pods[p] {
					t.Errorf("%s: %s names unknown pod %s", v.Name, w.Node, p)
				}
			}
		}
	}
	if !highYellow {
		t.Error("no case of an unplaceable high pod (Yellow, Task 2 ruling)")
	}
	if levels["green"] == 0 || levels["yellow"] == 0 || levels["red"] == 0 {
		t.Errorf("levels %v: every level needs a case", levels)
	}
}
