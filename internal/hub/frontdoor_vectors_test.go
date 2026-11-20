package hub

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFrontdoorVectorsCopy: testdata/frontdoor_vectors.json (the HA page's
// worst-case texts, contract §20.8) is a byte copy of core's
// domains/testdata/frontdoor_vectors.json (PORTCULLIS_CORE_DIR, else the
// sibling checkout; skipped without one, a failure when PORTCULLIS_CORE_DIR
// is set but unreadable).
func TestFrontdoorVectorsCopy(t *testing.T) {
	own, err := os.ReadFile("testdata/frontdoor_vectors.json")
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
	theirs, err := os.ReadFile(filepath.Join(core, "domains", "testdata", "frontdoor_vectors.json"))
	if err != nil {
		if set { // CI's core checkout (build.yml): the copy must be compared
			t.Fatalf("PORTCULLIS_CORE_DIR is set but core's file isn't readable: %v", err)
		}
		t.Skipf("no core checkout: %v", err)
	}
	if !bytes.Equal(own, theirs) {
		t.Error("testdata/frontdoor_vectors.json differs from core's domains/testdata/frontdoor_vectors.json: copy it byte for byte")
	}
}
