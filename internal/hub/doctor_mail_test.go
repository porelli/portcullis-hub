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

// TestDoctorMailUnavailable: mail on, mailctl down: no mail findings and
// mail_unavailable; mail off: neither.
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
		if strings.HasPrefix(fd.Kind, "mail_") {
			t.Fatalf("a mail finding while mailctl is down: %+v", fd)
		}
	}
	setCoreMail(t, f.fixture, false)
	if r, _ := f.h.Doctor(context.Background()); r.MailUnavailable {
		t.Fatal("mail_unavailable with mail off")
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
