package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// Sync timings (spec §8.12, §17 Q6).
var (
	ReportEvery  = 5 * time.Minute
	FallbackPull = 60 * time.Second
	ErrorBackoff = 60 * time.Second
)

// ErrRemoved: the Hub answered 403 removed.
var ErrRemoved = errors.New("this host was removed from Portcullis")

// StatusError lets Sync tell the Hub's answers apart (the api client's
// errors carry these).
type StatusError interface {
	error
	HTTPStatus() int
	Text() string
}

// SyncOptions are the agent's inputs.
type SyncOptions struct {
	Client Client
	Now    func() time.Time
	// Sleep waits (a var for tests); ctx ending stops it.
	Sleep func(ctx context.Context, d time.Duration)
	// Once runs a single round (tests, `host status --refresh`).
	Once bool
}

// SyncState is the loop's memory.
type SyncState struct {
	cfg      *AgentConfig
	signer   ssh.Signer
	ceiling  *cliapi.Ceiling
	st       *State
	bundle   *cliapi.Bundle
	findings []cliapi.Finding
	pull     bool
}

// Sync is `portcullis host sync`: long-poll for the bundle, apply it,
// report after every apply and at least every 5 minutes; on 404 or a cut
// connection fall back to a 60 s pull; a bad answer keeps the last files
// and never reloads sshd; 403 removed removes the Portcullis trust.
func Sync(ctx context.Context, sys System, o SyncOptions) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	cfg, err := LoadAgentConfig(sys)
	if err != nil {
		return err
	}
	signer, err := HostSigner(sys)
	if err != nil {
		return err
	}
	ceil, err := LoadCeiling(sys)
	if err != nil {
		return err
	}
	st, _ := LoadState(sys)
	s := &SyncState{cfg: cfg, signer: signer, ceiling: ceil, st: st}
	for ctx.Err() == nil {
		err := s.round(ctx, sys, o)
		switch {
		case errors.Is(err, ErrRemoved):
			log.Printf("portcullis: %v: removing the Portcullis trust", err)
			return RemoveTrust(ctx, sys, false, cfg.ServiceNone, true)
		case err != nil:
			log.Printf("portcullis: %v (the last files stay)", err)
			if o.Once {
				return err
			}
			o.Sleep(ctx, ErrorBackoff)
		case s.pull:
			if o.Once {
				return nil
			}
			o.Sleep(ctx, FallbackPull)
		}
		if o.Once {
			return nil
		}
	}
	return nil
}

func (s *SyncState) serial() int64 {
	if s.st == nil {
		return 0
	}
	return s.st.Serial
}

// round is one long-poll (or pull) and its apply and report.
func (s *SyncState) round(ctx context.Context, sys System, o SyncOptions) error {
	var b cliapi.Bundle
	path := "/api/cli/v1/hosts/bundle?since=" + strconv.FormatInt(s.serial(), 10)
	code, err := o.Client.Do(ctx, http.MethodGet, path, nil, &b, signRequest(s.signer, s.cfg.HostID, o.Now))
	if err != nil {
		var se StatusError
		if errors.As(err, &se) && se.HTTPStatus() == http.StatusForbidden && se.Text() == "removed" {
			return ErrRemoved
		}
		if code == http.StatusNotFound || code == 0 {
			s.pull = true // a proxy that cuts held connections, or no long-poll
		}
		s.maybeReport(ctx, sys, o, err)
		return err
	}
	if code == http.StatusNoContent {
		// Re-apply the last bundle when a report is due: hand-edited
		// managed files are rewritten (and reported fixed).
		if s.st != nil && o.Now().Sub(s.st.Applied) >= ReportEvery {
			if last := loadBundle(sys); last != nil && last.Serial == s.st.Serial && ValidateBundle(last, s.cfg.HostID, s.signer.PublicKey()) == nil {
				st, fs, err := Apply(ctx, sys, last, *s.ceiling, s.st, ApplyOptions{Domain: s.cfg.Domain, ServiceNone: s.cfg.ServiceNone, Now: o.Now()})
				s.bundle, s.findings = last, fs
				if err == nil {
					s.st = st
				}
				s.report(ctx, sys, o, err)
				return nil
			}
		}
		s.maybeReport(ctx, sys, o, nil)
		return nil
	}
	if err := ValidateBundle(&b, s.cfg.HostID, s.signer.PublicKey()); err != nil {
		e := fmt.Errorf("refused the bundle: %v", err)
		s.maybeReport(ctx, sys, o, e)
		return e
	}
	st, fs, err := Apply(ctx, sys, &b, *s.ceiling, s.st, ApplyOptions{Domain: s.cfg.Domain, ServiceNone: s.cfg.ServiceNone, Now: o.Now()})
	s.bundle, s.findings = &b, fs
	if err != nil {
		s.report(ctx, sys, o, err)
		return err
	}
	s.st = st
	saveBundle(sys, &b)
	s.report(ctx, sys, o, nil)
	return nil
}

// BundleFile is the last applied bundle (0600), re-applied to heal drift.
const BundleFile = "/etc/portcullis/bundle.json"

func saveBundle(sys System, b *cliapi.Bundle) {
	raw, err := json.Marshal(b)
	if err == nil {
		_ = sys.WriteFileAtomic(BundleFile, raw, 0o600)
	}
}

func loadBundle(sys System) *cliapi.Bundle {
	raw, err := sys.ReadFile(BundleFile)
	if err != nil || len(raw) > cliapi.MaxBundle {
		return nil
	}
	var b cliapi.Bundle
	if cliapi.UnmarshalStrict(raw, &b) != nil {
		return nil
	}
	return &b
}

func (s *SyncState) maybeReport(ctx context.Context, sys System, o SyncOptions, err error) {
	if s.st == nil || o.Now().Sub(s.st.Reported) >= ReportEvery {
		s.report(ctx, sys, o, err)
	}
}

func (s *SyncState) report(ctx context.Context, sys System, o SyncOptions, applyErr error) {
	since := time.Time{}
	if s.st != nil {
		since = s.st.Reported
	}
	r := BuildReport(ctx, sys, s.cfg.HostID, s.bundle, s.st, s.ceiling, s.findings, applyErr, since, o.Now())
	if _, err := o.Client.Do(ctx, http.MethodPost, "/api/cli/v1/hosts/report", r, nil, signRequest(s.signer, s.cfg.HostID, o.Now)); err != nil {
		log.Printf("portcullis: the report didn't reach the Hub: %v", err)
		return
	}
	if s.st != nil {
		s.st.Reported = o.Now().UTC()
		s.st.Removed = nil
		_ = SaveState(sys, s.st)
	}
}
