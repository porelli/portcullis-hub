package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// EnrollOptions are `portcullis host enroll`'s inputs.
type EnrollOptions struct {
	Code    *cliapi.EnrolCode
	Ceiling cliapi.Ceiling
	// NoBreakglass: --no-breakglass-i-have-console-access.
	NoBreakglass bool
	// Service is auto (systemd, then launchd, else refuse) or none.
	Service string
	Self    string
	CAFile  string
	// PeopleURL overrides https://people.<domain> (the container tests).
	PeopleURL string
	// Client talks to https://people.<domain>.
	Client Client
	Now    func() time.Time
}

// Enroll makes this a managed host (contract §18.11): the challenge and
// the proof by the host key, the first bundle (its user CA pinned by the
// code's fingerprint), every file, sshd checked and reloaded, the
// service. Any failure restores every file and leaves sshd as it was;
// the Hub is told when it can be.
func Enroll(ctx context.Context, sys System, o EnrollOptions) (err error) {
	if sys.GOOS() == "windows" {
		return errors.New("Windows hosts: follow the manual steps in the docs")
	}
	c := o.Code
	if o.Now == nil {
		o.Now = time.Now
	}
	if !o.Now().Before(c.Expires) {
		return errors.New("this enrolment code has expired: ask an administrator for a new one")
	}
	if err := o.Ceiling.Validate(); err != nil {
		return err
	}
	kind := ""
	if o.Service != "none" {
		if kind = serviceKind(sys); kind == "" {
			return fmt.Errorf("%v\n\nThe unit to install by hand:\n%s", ErrNoServiceManager, SyncUnitBody(o.Self))
		}
		if _, err := CheckRootExecutable(sys, o.Self); err != nil {
			return err
		}
	}
	version, err := CheckFloor(ctx, sys)
	if err != nil {
		return err
	}
	if err := CheckInclude(sys); err != nil {
		return err
	}
	if err := CheckBreakglass(sys, o.Ceiling.BreakglassAccount, o.NoBreakglass); err != nil {
		return err
	}
	signer, err := HostSigner(sys)
	if err != nil {
		return err
	}
	// The challenge and the proof.
	var ch cliapi.EnrolChallenge
	if _, err := o.Client.Do(ctx, http.MethodPost, "/api/cli/v1/hosts/enrol/challenge", cliapi.EnrolChallengeRequest{HostID: c.HostID}, &ch, nil); err != nil {
		return err
	}
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.EnrolMessage(c.Domain, c.HostID, ch.Challenge)), signer, sshsig.HashSHA512, cliapi.NSHostEnrol)
	if err != nil {
		return err
	}
	var b cliapi.Bundle
	req := cliapi.EnrolRequest{HostID: c.HostID, Secret: c.Secret, HostKey: cliapi.NormalAuthorizedKey(signer.PublicKey()),
		Proof: string(sshsig.Armor(sig)), SSHDVersion: version, Ceiling: o.Ceiling}
	if _, err := o.Client.Do(ctx, http.MethodPost, "/api/cli/v1/hosts/enrol", req, &b, nil); err != nil {
		return err
	}
	// The first user CA is pinned by the code.
	if len(b.UserCAs) == 0 {
		return errors.New("the first bundle has no user CA: refusing")
	}
	if k, _, err := cliapi.ParseAuthorizedKey(b.UserCAs[0]); err != nil || cliapi.Fingerprint(k) != c.UserCAFP {
		return errors.New("the server's user CA doesn't match the enrolment code's fingerprint: refusing, nothing was written")
	}
	if b.HostCertificate != "" {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(b.HostCertificate))
		cert, ok := k.(*ssh.Certificate)
		if err != nil || !ok || cliapi.Fingerprint(cert.SignatureKey) != c.HostCAFP {
			return errors.New("the host certificate isn't from the host CA the enrolment code names: refusing, nothing was written")
		}
	}
	if err := ValidateBundle(&b, c.HostID, signer.PublicKey()); err != nil {
		return fmt.Errorf("the first bundle is invalid: %v", err)
	}
	// Ceiling and agent config first (put back on failure), then apply.
	tx := NewTransaction(sys)
	report := func(applyErr error, st *State, fs []cliapi.Finding) {
		r := BuildReport(ctx, sys, c.HostID, &b, st, &o.Ceiling, fs, applyErr, time.Time{}, o.Now())
		_, _ = o.Client.Do(ctx, http.MethodPost, "/api/cli/v1/hosts/report", r, nil, signRequest(signer, c.HostID, o.Now))
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			report(err, nil, nil)
		}
	}()
	if err := sys.MkdirAll(ConfDir, 0o755); err != nil {
		return err
	}
	if err := tx.Stage(CeilingFile, CeilingBytes(o.Ceiling), 0o644); err != nil {
		return err
	}
	if err := tx.Stage(AgentFile, agentConfigBytes(AgentConfig{Domain: c.Domain, HostID: c.HostID, CAFile: o.CAFile, ServiceNone: o.Service == "none", PeopleURL: o.PeopleURL}), 0o600); err != nil {
		return err
	}
	if kind != "" {
		if err := stageService(tx, sys, kind, o.Self); err != nil {
			return err
		}
	}
	// Apply has its own transaction; its failure restores its files and
	// ours (the deferred rollback).
	st, fs, err := Apply(ctx, sys, &b, o.Ceiling, nil, ApplyOptions{Domain: c.Domain, ServiceNone: o.Service == "none", Now: o.Now()})
	if err != nil {
		return err
	}
	if err := tx.Commit(nil); err != nil {
		return err
	}
	if kind != "" {
		if err := startService(ctx, sys, kind); err != nil {
			return fmt.Errorf("the host is enrolled, but the sync service didn't start: %v", err)
		}
	}
	st.Reported = o.Now().UTC()
	_ = SaveState(sys, st)
	saveBundle(sys, &b)
	report(nil, st, fs)
	return nil
}
