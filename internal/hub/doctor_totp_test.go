package hub

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
)

type fakeTOTPKC struct {
	policy     *keycloak.OTPPolicy
	policyErr  error
	events     []keycloak.Event
	incomplete bool
	eventsErr  error
	block      bool // RealmLoginErrors waits for the deadline
	names      map[string]string
	namesErr   error
	from, to   time.Time
}

func (f *fakeTOTPKC) OTPPolicy(context.Context) (*keycloak.OTPPolicy, error) {
	return f.policy, f.policyErr
}
func (f *fakeTOTPKC) RealmLoginErrors(ctx context.Context, from, to time.Time) ([]keycloak.Event, bool, error) {
	f.from, f.to = from, to
	if f.block {
		<-ctx.Done()
		return nil, false, ctx.Err()
	}
	return f.events, f.incomplete, f.eventsErr
}
func (f *fakeTOTPKC) UsernamesByID(context.Context) (map[string]string, error) {
	return f.names, f.namesErr
}

func pinnedPolicy() *keycloak.OTPPolicy {
	return &keycloak.OTPPolicy{Type: "totp", Algorithm: "HmacSHA1", Digits: 6, Period: 30, LookAhead: 1, InitialCounter: 0, CodeReusable: false, ConfigureMaxAge: 300, DeleteMaxAge: 300}
}

// TestTOTPPolicyDrift: the pinned values (Global Constraints) give no
// drift; each differing one is named.
func TestTOTPPolicyDrift(t *testing.T) {
	if d := totpPolicyDrift(pinnedPolicy()); len(d) != 0 {
		t.Errorf("pinned: %v", d)
	}
	p := pinnedPolicy()
	p.Digits, p.CodeReusable, p.DeleteMaxAge, p.Algorithm = 8, true, 0, "HmacSHA256"
	want := []string{"otpPolicyAlgorithm", "otpPolicyDigits", "otpPolicyCodeReusable", "delete_credential max_auth_age"}
	if d := totpPolicyDrift(p); !slices.Equal(d, want) {
		t.Errorf("drift = %v, want %v", d, want)
	}
}

// TestDoctorTOTPInputs (T12, P16): the policy's drift; the realm's
// wrong-code counts per username over the last 24 h (pc_method totp
// only); an unreadable event read leaves the counts unknown (logged);
// an unreadable policy, or no Keycloak, no input at all.
func TestDoctorTOTPInputs(t *testing.T) {
	f := newFixture(t)
	if in := f.h.doctorTOTPIn(context.Background()); in != nil {
		t.Errorf("no Keycloak: %+v", in)
	}
	p := pinnedPolicy()
	p.Digits = 8
	ev := func(uid, method string) keycloak.Event {
		return keycloak.Event{Type: "LOGIN_ERROR", UserID: uid, Error: "invalid_user_credentials", Details: map[string]string{"pc_method": method}}
	}
	kc := &fakeTOTPKC{policy: p, names: map[string]string{"u1": "Alice", "u2": "bob"},
		events: []keycloak.Event{ev("u1", "totp"), ev("u1", "totp"), ev("u1", "password"), ev("u2", "totp"), ev("u9", "totp")}}
	f.h.SetTOTPKeycloak(kc)
	in := f.h.doctorTOTPIn(context.Background())
	if in == nil || !slices.Equal(in.PolicyDrift, []string{"otpPolicyDigits"}) || in.Wrong["alice"] != 2 || in.Wrong["bob"] != 1 || len(in.Wrong) != 2 {
		t.Fatalf("input = %+v", in)
	}
	if d := kc.to.Sub(kc.from); d != 24*time.Hour || in.Day != kc.to.UTC().Format("2006-01-02") {
		t.Errorf("window %v, day %s", d, in.Day)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	// Over the cap (review M1): counted anyway, capped said.
	kc.incomplete = true
	if in := f.h.doctorTOTPIn(context.Background()); in == nil || !in.Capped || in.Wrong["alice"] != 2 {
		t.Errorf("capped: %+v", in)
	}
	kc.incomplete = false
	kc.eventsErr = errors.New("keycloak: events: HTTP 500")
	if in := f.h.doctorTOTPIn(context.Background()); in == nil || in.Wrong != nil || in.Capped || len(in.PolicyDrift) != 1 {
		t.Errorf("events unreadable: %+v", in)
	}
	if !strings.Contains(logs.String(), "HTTP 500") {
		t.Errorf("log = %q", logs.String())
	}
	// The user list unreadable (review L3): counts unknown, drift kept.
	kc.eventsErr = nil
	kc.namesErr = errors.New("keycloak: users: HTTP 503")
	if in := f.h.doctorTOTPIn(context.Background()); in == nil || in.Wrong != nil || len(in.PolicyDrift) != 1 {
		t.Errorf("users unreadable: %+v", in)
	}
	if !strings.Contains(logs.String(), "HTTP 503") {
		t.Errorf("log = %q", logs.String())
	}
	// A read that never answers ends at the deadline (review L3).
	kc.namesErr = nil
	kc.block = true
	defer func(d time.Duration) { totpDoctorTimeout = d }(totpDoctorTimeout)
	totpDoctorTimeout = 50 * time.Millisecond
	start := time.Now()
	if in := f.h.doctorTOTPIn(context.Background()); in == nil || in.Wrong != nil || time.Since(start) > 5*time.Second {
		t.Errorf("deadline: %+v after %v", in, time.Since(start))
	}
	kc.block = false
	kc.policyErr = errors.New("keycloak down")
	if in := f.h.doctorTOTPIn(context.Background()); in != nil {
		t.Errorf("policy unreadable: %+v", in)
	}
}
