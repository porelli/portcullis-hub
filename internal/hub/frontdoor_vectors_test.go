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
// sibling checkout; the comparison is skipped without one).
func TestFrontdoorVectorsCopy(t *testing.T) {
	own, err := os.ReadFile("testdata/frontdoor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(own) {
		t.Fatal("the copy isn't valid JSON")
	}
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	theirs, err := os.ReadFile(filepath.Join(core, "domains", "testdata", "frontdoor_vectors.json"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	if !bytes.Equal(own, theirs) {
		t.Error("testdata/frontdoor_vectors.json differs from core's domains/testdata/frontdoor_vectors.json: copy it byte for byte")
	}
}
