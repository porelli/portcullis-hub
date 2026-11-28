package nodeagent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

type nodeClassVector struct {
	MemBytes      int64  `json:"mem_bytes"`
	CPU           int    `json:"cpu"`
	Model         string `json:"model"`
	PublicAnswers bool   `json:"public_answers"`
	Want          string `json:"want"`
}

// TestNodeClassVectorsShape: nodeclass_vectors.json (class.Suggest,
// contract §20.1) decodes strictly and covers each rule: below 3.5 GiB →
// small (both sides of 3 758 096 384 bytes), a Raspberry Pi → small, a
// public answer → cloud, else home.
func TestNodeClassVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeclass_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []nodeClassVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 8 {
		t.Fatalf("%d vectors", len(vs))
	}
	n := map[string]int{}
	for _, v := range vs {
		switch v.Want {
		case "small", "home", "cloud":
			n[v.Want]++
		default:
			t.Errorf("want %q", v.Want)
		}
	}
	if n["small"] < 3 || n["home"] < 2 || n["cloud"] < 2 {
		t.Errorf("coverage %v", n)
	}
	const limit = 3758096384
	below, at := false, false
	for _, v := range vs {
		if v.Model == "" && !v.PublicAnswers {
			below = below || (v.MemBytes == limit-1 && v.Want == "small")
			at = at || (v.MemBytes == limit && v.Want == "home")
		}
		if v.Model == "" && v.MemBytes >= limit && v.Want == "small" {
			t.Errorf("%d bytes is small: the limit is 3.5 GiB", v.MemBytes)
		}
	}
	if !below || !at {
		t.Error("the 3.5 GiB boundary isn't pinned on both sides")
	}
}

// TestNodeClassVectors: Suggest answers every vector.
func TestNodeClassVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeclass_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []nodeClassVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if got := Suggest(v.MemBytes, v.CPU, v.Model, v.PublicAnswers); got != v.Want {
			t.Errorf("Suggest(%d, %d, %q, %v) = %s, want %s", v.MemBytes, v.CPU, v.Model, v.PublicAnswers, got, v.Want)
		}
	}
}

// TestNodeagentCallVectorsCopy: testdata/nodeagent_call_vectors.json is
// core's nodeadm/testdata/nodeagent_call_vectors.json byte for byte.
func TestNodeagentCallVectorsCopy(t *testing.T) {
	own, err := os.ReadFile("testdata/nodeagent_call_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(own) {
		t.Fatal("the copy isn't valid JSON")
	}
	core, set := os.LookupEnv("PORTCULLIS_CORE_DIR")
	if !set {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	theirs, err := os.ReadFile(filepath.Join(core, "nodeadm", "testdata", "nodeagent_call_vectors.json"))
	if err != nil {
		if set {
			t.Fatalf("PORTCULLIS_CORE_DIR is set but core's file isn't readable: %v", err)
		}
		t.Skipf("no core checkout: %v", err)
	}
	if !bytes.Equal(own, theirs) {
		t.Error("testdata/nodeagent_call_vectors.json differs from core's nodeadm/testdata/nodeagent_call_vectors.json: copy it byte for byte")
	}
}

// TestJoinFlagsVectorsCopy: testdata/join_flags_vectors.json is core's
// nodeadm/testdata/join_flags_vectors.json byte for byte.
func TestJoinFlagsVectorsCopy(t *testing.T) {
	own, err := os.ReadFile("testdata/join_flags_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(own) {
		t.Fatal("the copy isn't valid JSON")
	}
	core, set := os.LookupEnv("PORTCULLIS_CORE_DIR")
	if !set {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	theirs, err := os.ReadFile(filepath.Join(core, "nodeadm", "testdata", "join_flags_vectors.json"))
	if err != nil {
		if set {
			t.Fatalf("PORTCULLIS_CORE_DIR is set but core's file isn't readable: %v", err)
		}
		t.Skipf("no core checkout: %v", err)
	}
	if !bytes.Equal(own, theirs) {
		t.Error("testdata/join_flags_vectors.json differs from core's nodeadm/testdata/join_flags_vectors.json: copy it byte for byte")
	}
}

// TestHealthAnswerVectors (core Task 33b security review): the shared
// health answers decode strictly into Health, device_peers by public key
// (an object, or null for an unreadable device: never confused).
func TestHealthAnswerVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeagent_call_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Answers []struct {
			Name   string          `json:"name"`
			Answer json.RawMessage `json:"answer"`
		} `json:"health_answers"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Answers) != 3 {
		t.Fatalf("health_answers: %v (%d)", err, len(f.Answers))
	}
	for i, a := range f.Answers {
		var h Health
		if err := jsonstrict.Decode(a.Answer, &h); err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		if (i == 2) == h.DevicePeers.Valid {
			t.Errorf("%s: device_peers %+v", a.Name, h.DevicePeers)
		}
		for k, p := range h.DevicePeers.V {
			if len(k) != 44 || len(p.AllowedIPs) == 0 {
				t.Errorf("%s: device peer %q %+v", a.Name, k, p)
			}
		}
	}
}
