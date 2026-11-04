package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("shared_path", "/srv/media", "jellyfin/movies", "samba/share")
	b := Fingerprint("shared_path", "samba/share", "/srv/media", "jellyfin/movies")
	if a != b {
		t.Errorf("order matters: %s != %s", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fp %q: want 16 hex digits", a)
	}
	if c := Fingerprint("must_own_conflict", "/srv/media", "jellyfin/movies", "samba/share"); c == a {
		t.Error("kind doesn't matter")
	}
	// Subjects are separated: ("ab", "c") is not ("a", "bc").
	if Fingerprint("k", "ab", "c") == Fingerprint("k", "a", "bc") {
		t.Error("subjects not separated")
	}
}

func TestDigestCanonical(t *testing.T) {
	if Digest(map[string]int{"a": 1, "b": 2}) != Digest(map[string]int{"b": 2, "a": 1}) {
		t.Error("map order matters")
	}
	if Digest([]string{"a"}) == Digest([]string{"b"}) {
		t.Error("digest ignores content")
	}
}

// stubCheck emits the findings it holds.
type stubCheck struct {
	kind string
	out  []Finding
}

func (s stubCheck) Kind() string             { return s.kind }
func (s stubCheck) Run(in *Inputs) []Finding { return s.out }

func withOnly(t *testing.T, cs ...Check) {
	t.Helper()
	regMu.Lock()
	saved := registry
	registry = append([]Check(nil), cs...)
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		registry = saved
		regMu.Unlock()
	})
}

func TestMuteReappearsOnChange(t *testing.T) {
	f := Finding{FP: Fingerprint("stub", "x"), Kind: "stub", Severity: Warning, Title: "x", Inputs: Digest("A")}
	withOnly(t, stubCheck{kind: "stub", out: []Finding{f}})
	first := Run(&Inputs{}, nil)
	if len(first.Findings) != 1 || first.Counts[Warning] != 1 || first.Muted != 0 {
		t.Fatalf("unmuted report = %+v", first)
	}
	digest := first.Findings[0].Inputs
	// H8: the report carries the digest as the finding's token.
	if first.Findings[0].Token != digest || digest == "" {
		t.Errorf("token %q, digest %q", first.Findings[0].Token, digest)
	}
	mutes := map[string]Mute{f.FP: {Reason: "known", Actor: "root", At: time.Now(), Inputs: digest}}
	r := Run(&Inputs{}, mutes)
	if r.Muted != 1 || r.Counts[Warning] != 0 || r.Findings[0].Muted == nil || r.Findings[0].Muted.Reason != "known" {
		t.Fatalf("muted report = %+v", r)
	}
	// Inputs B: the mute no longer applies.
	f.Inputs = Digest("B")
	withOnly(t, stubCheck{kind: "stub", out: []Finding{f}})
	r = Run(&Inputs{}, mutes)
	if r.Muted != 0 || r.Counts[Warning] != 1 || r.Findings[0].Muted != nil {
		t.Fatalf("changed inputs still muted: %+v", r)
	}
	// The same inputs at a higher severity: not muted either.
	f.Inputs, f.Severity = Digest("A"), Problem
	withOnly(t, stubCheck{kind: "stub", out: []Finding{f}})
	r = Run(&Inputs{}, mutes)
	if r.Muted != 0 || r.Counts[Problem] != 1 {
		t.Fatalf("a severity rise stayed muted: %+v", r)
	}
}

func TestRegisterCustomCheck(t *testing.T) {
	withOnly(t)
	Register(stubCheck{kind: "file_share_password", out: []Finding{{Kind: "file_share_password", Severity: Info, Title: "custom"}}})
	r := Run(&Inputs{}, nil)
	if len(r.Findings) != 1 || r.Findings[0].Kind != "file_share_password" || r.Findings[0].FP == "" {
		t.Fatalf("report = %+v", r)
	}
}

func TestRunSortsAndMerges(t *testing.T) {
	fpA := Fingerprint("k", "a")
	withOnly(t,
		stubCheck{kind: "k", out: []Finding{
			{FP: Fingerprint("k", "c"), Kind: "k", Severity: Info, Title: "b"},
			{FP: fpA, Kind: "k", Severity: Warning, Title: "same"},
			{FP: Fingerprint("k", "b"), Kind: "k", Severity: Problem, Title: "z"},
		}},
		// A second check of the same kind and fingerprint (the disk part):
		// the higher severity wins.
		stubCheck{kind: "k", out: []Finding{{FP: fpA, Kind: "k", Severity: Problem, Title: "same"}}},
	)
	r := Run(&Inputs{}, nil)
	var got []string
	for _, f := range r.Findings {
		got = append(got, string(f.Severity)+":"+f.Title)
	}
	if strings.Join(got, ",") != "problem:same,problem:z,info:b" {
		t.Errorf("order = %v", got)
	}
	if r.Counts[Problem] != 2 || r.Counts[Info] != 1 || r.Counts[Warning] != 0 {
		t.Errorf("counts = %v", r.Counts)
	}
}

func TestRunScans(t *testing.T) {
	withOnly(t)
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	r := Run(&Inputs{Scans: map[string]ScanIn{"/srv/b": {At: at, Target: "/srv/b"}, "/srv/a": {At: at, Target: "/srv/a"}}}, nil)
	if len(r.Scans) != 2 || r.Scans[0].Target != "/srv/a" {
		t.Errorf("scans = %+v", r.Scans)
	}
	if r.Findings == nil {
		t.Error("findings must be [] in JSON, not null")
	}
}

// H11 M3: findings sharing a fingerprint fold every digest into the kept
// one: new evidence from the lower-ranked check lifts a mute too.
func TestSameFPFoldsDigests(t *testing.T) {
	fp := Fingerprint("stub", "x")
	static := Finding{FP: fp, Kind: "stub", Severity: Problem, Title: "static", Inputs: Digest("S")}
	runtime := Finding{FP: fp, Kind: "stub", Severity: Problem, Title: "runtime", Inputs: Digest("R1")}
	withOnly(t, stubCheck{kind: "stub", out: []Finding{static}}, stubCheck{kind: "stub", out: []Finding{runtime}})
	first := Run(&Inputs{}, nil)
	if len(first.Findings) != 1 || first.Findings[0].Title != "static" {
		t.Fatalf("report = %+v", first)
	}
	mutes := map[string]Mute{fp: {Reason: "known", Inputs: first.Findings[0].Inputs}}
	if r := Run(&Inputs{}, mutes); r.Muted != 1 {
		t.Fatalf("not muted: %+v", r)
	}
	runtime.Inputs = Digest("R2")
	withOnly(t, stubCheck{kind: "stub", out: []Finding{static}}, stubCheck{kind: "stub", out: []Finding{runtime}})
	if r := Run(&Inputs{}, mutes); r.Muted != 0 || r.Findings[0].Title != "static" {
		t.Fatalf("new runtime evidence stayed muted: %+v", r)
	}
	// A lone finding keeps its own digest (existing mutes hold).
	withOnly(t, stubCheck{kind: "stub", out: []Finding{static}})
	if r := Run(&Inputs{}, nil); r.Findings[0].Inputs != Digest([]string{string(Problem), Digest("S")}) {
		t.Errorf("lone digest changed: %s", r.Findings[0].Inputs)
	}
}
