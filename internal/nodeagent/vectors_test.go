package nodeagent

import (
	"os"
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
