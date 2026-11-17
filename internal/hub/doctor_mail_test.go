package hub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

func findKind(r *doctor.Report, kind string) *doctor.Finding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind {
			return &r.Findings[i]
		}
	}
	return nil
}

// TestDmarcPromoteFixConfirms: the doctor offers mail_dmarc_promote for
// a proposal; the preview is one line with a plan hash; the apply runs
// mailctl's action; the AI can't apply it without a confirmation; a
// proposal gone since the preview is 409.
func TestDmarcPromoteFixConfirms(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	ctx := context.Background()
	q := "quarantine"
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.StatusV.DMARC = []mailprovider.StatusDMARC{{Domain: "example.org", Policy: "none", Proposed: &q}}
	})
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fd := findKind(r, doctor.KindMailDMARCPromote)
	if fd == nil || fd.FixKind != doctor.FixMailDMARCPromote || fd.Class != doctor.FixOneClick || fd.Domains[0] != "example.org" {
		t.Fatalf("finding %+v", fd)
	}
	p, err := f.h.PreviewFix(ctx, fd.FP, nil)
	if err != nil || len(p.Lines) != 1 || p.Lines[0] != "example.org: DMARC p=none → p=quarantine" || p.Hash == "" {
		t.Fatalf("preview %+v %v", p, err)
	}
	if need, err := f.h.FixNeedsConfirmation(ctx, nil, fd.FP, nil, p.Hash); err != nil || !need {
		t.Fatalf("needs confirmation: %v %v", need, err)
	}
	ai := directory.Actor{User: "root", Via: directory.ViaAI, Client: "claude"}
	if _, err := f.h.ApplyFix(ctx, fd.FP, nil, p.Hash, ai); statusOf(err) != 409 {
		t.Fatalf("AI without a confirmation: %v", err)
	}
	if _, err := f.h.ApplyFix(ctx, fd.FP, nil, p.Hash, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lo := f.h.LastOp(opKeyDomain("example.org")); lo != nil && !lo.Running {
			if !lo.OK {
				t.Fatalf("op %+v", lo)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var acts []string
	f.mc.Lock(func(s *mailprovidertest.Server) { acts = append(acts, s.Actions...) })
	if strings.Join(acts, ",") != "dmarc-promote example.org" {
		t.Fatalf("actions %v", acts)
	}
	// The proposal changed since the preview: 409.
	r2 := "reject"
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.DMARC[0].Proposed = &r2 })
	if _, _, h2, err := f.h.mailFixPlan(ctx, doctor.FixMailDMARCPromote, *fd, nil); err != nil || h2 == p.Hash {
		t.Fatalf("hash unchanged after the proposal changed (%v)", err)
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.DMARC = nil })
	if _, err := f.h.PreviewFixIn(ctx, r, fd.FP, nil); statusOf(err) != 409 {
		t.Fatalf("proposal gone: %v", err)
	}
}

// TestDoctorMailUnavailable: mail on, the provider down: no provider
// findings and mail_unavailable; mail off: neither.
func TestDoctorMailUnavailable(t *testing.T) {
	f := newMailFixture(t)
	f.mc.Close()
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.MailUnavailable {
		t.Fatal("no mail_unavailable")
	}
	for _, fd := range r.Findings {
		if strings.HasPrefix(fd.Kind, "mail_") && fd.Kind != doctor.KindMailTimerMissing {
			t.Fatalf("a mail finding before 10 min: %+v", fd)
		}
	}
	setCoreMail(t, f.fixture, false)
	if r, _ := f.h.Doctor(context.Background()); r.MailUnavailable {
		t.Fatal("mail_unavailable with mail off")
	}
}

// TestDoctorProviderUnreachable: unanswered since 10 min is the Problem;
// answering again clears it.
func TestDoctorProviderUnreachable(t *testing.T) {
	w := wiredFix(t)
	w.mc.Lock(func(s *mailprovidertest.Server) { s.Down = true })
	r, _ := w.h.Doctor(context.Background())
	if findKind(r, doctor.KindMailProviderUnreach) != nil {
		t.Fatal("unreachable at once")
	}
	w.advance(11 * time.Minute)
	r, _ = w.h.Doctor(context.Background())
	if fd := findKind(r, doctor.KindMailProviderUnreach); fd == nil || fd.Severity != doctor.Problem {
		t.Fatalf("%+v", r.Findings)
	}
	w.mc.Lock(func(s *mailprovidertest.Server) { s.Down = false })
	r, _ = w.h.Doctor(context.Background())
	if findKind(r, doctor.KindMailProviderUnreach) != nil {
		t.Fatal("still unreachable")
	}
}

// TestDoctorHubJudgedKinds: nothing wired, a failing owed void, a hold,
// a refused set: each its kind, from the Hub's own state.
func TestDoctorHubJudgedKinds(t *testing.T) {
	f := newWireFix(t)
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findKind(r, doctor.KindMailProviderMissing) == nil {
		t.Fatalf("missing: %+v", r.Findings)
	}
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Held = &state.MailHold{Reason: MailHoldText}
	w.h.mu.Unlock()
	w.h.mailDNSProb.mu.Lock()
	w.h.mailDNSProb.sets = map[string]string{"team-b.example.net": "mail set: team-b.example.net A: A records are not allowed"}
	w.h.mailDNSProb.mu.Unlock()
	r, _ = w.h.Doctor(context.Background())
	if findKind(r, doctor.KindMailProviderRefused) == nil || findKind(r, doctor.KindMailRecordsWrong) == nil {
		t.Fatalf("refused/records: %+v", r.Findings)
	}
	w.h.mu.Lock()
	w.h.st.Mail.Held = nil
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	w.h.mu.Unlock()
	w.h.setMailVoidErr("the provider's void failed: 500")
	r, _ = w.h.Doctor(context.Background())
	if fd := findKind(r, doctor.KindMailVoidPending); fd == nil || !strings.Contains(fd.Why, "void failed") {
		t.Fatalf("void: %+v", r.Findings)
	}
}

// TestDoctorMailRestartFailed: a failed restart of mail shows as
// mail_rate_held "mail sessions may still be open".
func TestDoctorMailRestartFailed(t *testing.T) {
	f := newMailFixture(t)
	f.engine.mu.Lock()
	f.engine.restartErr = errTestRestart
	f.engine.mu.Unlock()
	f.h.mailRestart(context.Background(), "a test")
	r, _ := f.h.Doctor(context.Background())
	fd := findKind(r, doctor.KindMailRateHeld)
	if fd == nil || fd.Severity != doctor.Warning || !strings.Contains(fd.Why, doctor.MailSessionsLine) {
		t.Fatalf("finding %+v", fd)
	}
}

var errTestRestart = &StatusError{Status: 500, Err: errTestRestartText}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTestRestartText = testErr("the engine refused the restart")

// TestDoctorBootstrapFalseIsProblem (core: a key file that doesn't match
// the store makes the adapter fail closed, GET /v1/state bootstrap:
// false, every other route 503): a Problem once it lasts 10 min.
func TestDoctorBootstrapFalseIsProblem(t *testing.T) {
	w := wiredFix(t)
	w.mc.Lock(func(s *mailprovidertest.Server) { s.Bootstrap = false })
	r, _ := w.h.Doctor(context.Background())
	if !r.MailUnavailable {
		t.Fatal("no mail_unavailable")
	}
	w.advance(11 * time.Minute)
	r, _ = w.h.Doctor(context.Background())
	fd := findKind(r, doctor.KindMailProviderUnreach)
	if fd == nil || fd.Severity != doctor.Problem || !strings.Contains(fd.Why, "bootstrap: false") {
		t.Fatalf("%+v", r.Findings)
	}
}
