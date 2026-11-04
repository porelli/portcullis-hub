package doctor

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

func TestPersonOptionFindings(t *testing.T) {
	base := PersonIn{Instance: "timemachine", Key: "quota", Label: "Backup size limit", DefaultDisplay: "500 GiB"}

	noRows := of(t, "person_option", &Inputs{Person: []PersonIn{base}})
	if len(noRows) != 1 || noRows[0].Severity != Info ||
		noRows[0].Title != "timemachine: Backup size limit has no group values; everyone with access gets the default (500 GiB)." {
		t.Fatalf("no rows = %+v", noRows)
	}

	req := base
	req.Requires = &templates.Check{Kind: templates.CheckRequiresGroupValue, Reason: "Set a quota per group or disks fill up"}
	got := of(t, "person_option", &Inputs{Person: []PersonIn{req}})
	if len(got) != 1 || got[0].Severity != Warning || !strings.Contains(got[0].Why, "Set a quota per group or disks fill up") {
		t.Fatalf("requires = %+v", got)
	}
	if got[0].FP == noRows[0].FP {
		// Same subject; fine either way, but a severity rise must not stay
		// muted (Run's digest covers the severity).
		_ = got
	}

	// Unbound rows (id 0) and rows of deleted groups count as no rows.
	unbound := base
	unbound.Rows = []RowIn{{Group: "users_timemachine", GroupID: 0, Exists: true}}
	if got := of(t, "person_option", &Inputs{Person: []PersonIn{unbound}}); len(got) != 1 || got[0].Severity != Info {
		t.Fatalf("unbound = %+v", got)
	}

	rows := base
	rows.Rows = []RowIn{
		{Group: "family", GroupID: 3, Exists: true, Members: 0},
		{Group: "gone", GroupID: 4, Exists: false},
		{Group: "ok", GroupID: 5, Exists: true, Members: 2},
		{Group: "unknown", GroupID: 6, Exists: true, Members: -1}, // directory down: not judged
	}
	got = of(t, "person_option", &Inputs{Person: []PersonIn{rows}})
	if len(got) != 2 {
		t.Fatalf("rows = %+v", got)
	}
	var empty, gone *Finding
	for i := range got {
		switch {
		case strings.Contains(got[i].Title, "family"):
			empty = &got[i]
		case strings.Contains(got[i].Title, "gone"):
			gone = &got[i]
		}
	}
	if empty == nil || empty.Severity != Warning || gone == nil || gone.Severity != Warning || empty.FP == gone.FP {
		t.Fatalf("rows = %+v", got)
	}
	for _, f := range append(got, noRows...) {
		if f.Class != FixLink || f.Link == nil || f.Link.Instance != "timemachine" || f.Link.Option != "quota" {
			t.Errorf("link = %+v", f)
		}
	}
}
