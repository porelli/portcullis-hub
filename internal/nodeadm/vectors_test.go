package nodeadm

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestNodeadmVectorsCopy: testdata/nodeadm_api_vectors.json is a byte copy
// of core's nodeadm/testdata/nodeadm_api_vectors.json (contract §20.2; the
// core checkout from PORTCULLIS_CORE_DIR, else the sibling checkout;
// the comparison is skipped without one, the copy itself must exist).
func TestNodeadmVectorsCopy(t *testing.T) {
	own, err := os.ReadFile("testdata/nodeadm_api_vectors.json")
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
	theirs, err := os.ReadFile(filepath.Join(core, "nodeadm", "testdata", "nodeadm_api_vectors.json"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	if !bytes.Equal(own, theirs) {
		t.Error("testdata/nodeadm_api_vectors.json differs from core's nodeadm/testdata/nodeadm_api_vectors.json: copy it byte for byte")
	}
}
