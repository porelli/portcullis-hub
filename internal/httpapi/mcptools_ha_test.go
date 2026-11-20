package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
	sdk "github.com/portcullis/hub/internal/mcpsdk"
)

// TestHAFindingsToolNoSecrets (Q-M5): on Kubernetes ha_findings answers
// real HA findings (a lost Lease, nodeadm's error, the backup's) and its
// JSON holds no secret of the Hub: no file under the data or project
// directory's secrets, no private key, no join code or k3s token, no
// test secret.
func TestHAFindingsToolNoSecrets(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	e.s.Hub.SetPeople(e.s.Directory)
	e.s.registerMCPTools()
	e.s.Hub.SetHADoctorForTest(func() error { return errors.New("this Hub is standing by: another Hub is the active writer") },
		func(context.Context) (*time.Time, error) { return nil, errors.New("the destination answered 403") },
		func(context.Context, string) bool { return true })
	var tool *Tool
	for _, tl := range e.s.tools(ScopeAdmin) {
		if tl.Name == "ha_findings" {
			tl := tl
			tool = &tl
		}
	}
	if tool == nil || tool.Class != ClassRead || tool.Twin != "GET /api/doctor" {
		t.Fatalf("ha_findings: %+v", tool)
	}
	ai := &directory.Caller{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	run := func() (string, *hub.HAFindings) {
		t.Helper()
		v, err := tool.Run(context.Background(), ai, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(sdk.TextOf(toolError(err, func(s string) string { return s })))
		}
		b, _ := json.Marshal(v)
		var out hub.HAFindings
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return string(b), &out
	}
	txt, v := run()
	kinds := map[string]bool{}
	for _, f := range v.Findings {
		kinds[f.Kind] = true
	}
	if !kinds[doctor.KindHALeaseLost] {
		t.Errorf("no ha_lease_lost in %s", txt)
	}
	// nodeadm failing: the N−1 kind's "can't judge" (the snapshot of
	// three nodes was read once before).
	e.na.mu.Lock()
	e.na.err = errors.New("nodeadm: 503 not_leader")
	e.na.mu.Unlock()
	txt2, v2 := run()
	found := false
	for _, f := range v2.Findings {
		found = found || (f.Kind == doctor.KindHANMinus1Insufficient && strings.Contains(f.Why, "not_leader"))
	}
	if !found {
		t.Errorf("nodeadm error not judged: %s", txt2)
	}
	markers := []string{"PRIVATE KEY", "pcj2.", "K10", testSecret, testMCPSecret}
	filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.Contains(p, "secret") {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			if v := strings.TrimSpace(string(b)); len(v) >= 16 {
				markers = append(markers, v)
			}
		}
		return nil
	})
	for _, out := range []string{txt, txt2} {
		for _, m := range markers {
			if strings.Contains(out, m) {
				t.Errorf("ha_findings holds a secret (%.8s…): %s", m, out)
			}
		}
	}
}
