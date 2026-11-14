package hub

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
)

// TOTPKeycloak is the Keycloak side of the authenticator-app doctor kinds
// (implemented by *keycloak.Client).
type TOTPKeycloak interface {
	OTPPolicy(ctx context.Context) (*keycloak.OTPPolicy, error)
	RealmLoginErrors(ctx context.Context, from, to time.Time) ([]keycloak.Event, error)
	UsernamesByID(ctx context.Context) (map[string]string, error)
}

// totpDoctor is the wiring of the authenticator-app doctor kinds (its own
// leaf lock: read before the doctor takes mu).
type totpDoctor struct {
	mu sync.Mutex
	kc TOTPKeycloak
}

// SetTOTPKeycloak wires the authenticator-app doctor kinds' Keycloak
// reads (main: the Keycloak client; nil: the kinds never fire).
func (h *Hub) SetTOTPKeycloak(k TOTPKeycloak) {
	h.totpDoc.mu.Lock()
	defer h.totpDoc.mu.Unlock()
	h.totpDoc.kc = k
}

// totpDoctorTimeout bounds the authenticator-app inputs' Keycloak reads.
const totpDoctorTimeout = 10 * time.Second

// totpPolicyDrift names each setting of p that differs from the pinned
// policy (contract §8.1 "Authenticator-app codes", core's
// KC_REALM_OTP_SETTINGS), in this order.
func totpPolicyDrift(p *keycloak.OTPPolicy) []string {
	var out []string
	add := func(bad bool, name string) {
		if bad {
			out = append(out, name)
		}
	}
	add(p.Type != "totp", "otpPolicyType")
	add(p.Algorithm != "HmacSHA1", "otpPolicyAlgorithm")
	add(p.Digits != 6, "otpPolicyDigits")
	add(p.Period != 30, "otpPolicyPeriod")
	add(p.LookAhead != 1, "otpPolicyLookAheadWindow")
	add(p.CodeReusable, "otpPolicyCodeReusable")
	add(p.InitialCounter != 0, "otpPolicyInitialCounter")
	add(p.ConfigureMaxAge != 300, "CONFIGURE_TOTP max_auth_age")
	add(p.DeleteMaxAge != 300, "delete_credential max_auth_age")
	return out
}

// doctorTOTPIn gathers the authenticator-app kinds' input outside mu
// (10 s): the policy's drift, and each person's LOGIN_ERROR events with
// pc_method totp in the last 24 h, from one realm-wide read (P16) keyed by
// LLDAP username. No Keycloak, or an unreadable policy: nil (no findings,
// the cause logged). An unreadable or incomplete event read: the counts
// are unknown (nil, logged), the drift still judged.
func (h *Hub) doctorTOTPIn(ctx context.Context) *doctor.SignInTOTPIn {
	h.totpDoc.mu.Lock()
	kc := h.totpDoc.kc
	h.totpDoc.mu.Unlock()
	if kc == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, totpDoctorTimeout)
	defer cancel()
	p, err := kc.OTPPolicy(ctx)
	if err != nil || p == nil {
		log.Printf("doctor: Keycloak's OTP policy can't be read (%v): the authenticator-app checks are skipped", err)
		return nil
	}
	now := time.Now().UTC()
	in := &doctor.SignInTOTPIn{PolicyDrift: totpPolicyDrift(p), Day: now.Format("2006-01-02")}
	evs, err := kc.RealmLoginErrors(ctx, now.Add(-24*time.Hour), now)
	if err != nil {
		log.Printf("doctor: the realm's sign-in errors can't be read (%v): no authenticator-code guessing check", err)
		return in
	}
	names, err := kc.UsernamesByID(ctx)
	if err != nil {
		log.Printf("doctor: Keycloak's users can't be read (%v): no authenticator-code guessing check", err)
		return in
	}
	in.Wrong = map[string]int{}
	for _, e := range evs {
		if e.Type != "LOGIN_ERROR" || strings.TrimSpace(e.Details["pc_method"]) != string(signin.TOTP) {
			continue
		}
		u := strings.ToLower(names[e.UserID])
		if u == "" {
			continue // a user Keycloak no longer lists
		}
		in.Wrong[u]++
	}
	return in
}
