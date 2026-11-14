package doctor

import (
	"fmt"
	"sort"
	"strings"
)

// Authenticator-app checks (contract §14.5, authenticator codes): the
// realm's OTP policy as core configures it, and people whose codes are
// being guessed.

// SignInTOTPIn is the authenticator-app kinds' input (nil: it couldn't be
// gathered; no findings of these kinds). PolicyDrift names each realm
// setting that differs from the pinned policy (otpPolicyDigits, …; nil =
// none, or unknown); Wrong counts each person's LOGIN_ERROR events with
// pc_method totp in the last 24 h (nil = unknown); Day is today
// (yyyy-mm-dd, UTC), the guessing findings' fingerprint subject. Capped:
// the read stopped at its 1,000-event cap (review M1): the counts are
// lower bounds, still judged.
type SignInTOTPIn struct {
	PolicyDrift []string
	Wrong       map[string]int
	Capped      bool
	Day         string
}

// The authenticator-app kinds.
const (
	KindSignInTOTPPolicyDrift = "signin_totp_policy_drift"
	KindSignInTOTPGuessing    = "signin_totp_guessing"
	// KindSignInLoginErrorsCapped (Info): the guessing check's read hit
	// its cap; one per day (Fingerprint(kind, day)).
	KindSignInLoginErrorsCapped = "signin_login_errors_capped"
)

// TOTPGuessingThreshold is how many wrong codes in 24 h make a finding.
const TOTPGuessingThreshold = 20

func init() {
	Register(signInTOTPDriftCheck{})
	Register(signInTOTPGuessingCheck{})
	Register(signInLoginErrorsCappedCheck{})
}

type signInLoginErrorsCappedCheck struct{}

func (signInLoginErrorsCappedCheck) Kind() string { return KindSignInLoginErrorsCapped }

func (signInLoginErrorsCappedCheck) Run(in *Inputs) []Finding {
	t := in.SignInTOTP
	if t == nil || !t.Capped {
		return nil
	}
	return []Finding{{
		FP: Fingerprint(KindSignInLoginErrorsCapped, t.Day), Kind: KindSignInLoginErrorsCapped, Severity: Info,
		Title: "LOGIN_ERROR read capped at 1,000 events: counts are lower bounds",
		Why: "More than 1,000 sign-ins failed in the last 24 hours. The authenticator-code guessing check read the newest 1,000 only, " +
			"so each person's count of wrong codes may be higher than shown; anyone at 20 or more is still reported. " +
			"Many failed sign-ins with unknown usernames can be someone trying to hide a guessing attempt.",
		Class:  FixExplain,
		Steps:  []string{"Read Keycloak's events (Realm settings → Events) for the last day and see who is failing to sign in."},
		Inputs: Digest([]any{t.Day, true}),
	}}
}

type signInTOTPDriftCheck struct{}

func (signInTOTPDriftCheck) Kind() string { return KindSignInTOTPPolicyDrift }

func (signInTOTPDriftCheck) Run(in *Inputs) []Finding {
	t := in.SignInTOTP
	if t == nil || len(t.PolicyDrift) == 0 {
		return nil
	}
	names := append([]string(nil), t.PolicyDrift...)
	sort.Strings(names)
	return []Finding{{
		FP: Fingerprint(KindSignInTOTPPolicyDrift), Kind: KindSignInTOTPPolicyDrift, Severity: Problem,
		Title: "Keycloak's authenticator-app settings differ from Portcullis's.",
		Why: fmt.Sprintf("These Keycloak settings aren't what Portcullis sets (6 digits, 30 seconds, SHA-1, a code used once, re-authentication within 5 minutes to add or remove one): %s. "+
			"Codes may stop matching people's apps, or be accepted for longer than they should.", strings.Join(names, ", ")),
		Class:  FixExplain,
		Steps:  []string{"On the server, run `./portcullis keycloak configure`: it sets the realm's OTP policy and the two required actions back."},
		Inputs: Digest(names),
	}}
}

type signInTOTPGuessingCheck struct{}

func (signInTOTPGuessingCheck) Kind() string { return KindSignInTOTPGuessing }

func (signInTOTPGuessingCheck) Run(in *Inputs) []Finding {
	t := in.SignInTOTP
	if t == nil || t.Wrong == nil {
		return nil
	}
	users := make([]string, 0, len(t.Wrong))
	for u, n := range t.Wrong {
		if n >= TOTPGuessingThreshold {
			users = append(users, u)
		}
	}
	sort.Strings(users)
	var out []Finding
	for _, u := range users {
		n := t.Wrong[u]
		out = append(out, Finding{
			FP: Fingerprint(KindSignInTOTPGuessing, u, t.Day), Kind: KindSignInTOTPGuessing, Severity: Warning,
			Title:   fmt.Sprintf("Someone is guessing %s's authenticator codes.", u),
			Why:     fmt.Sprintf("In the last 24 hours %s's password was accepted and then the authenticator code was wrong %d times. Someone may know the password.", u, n),
			Persons: []string{u},
			Class:   FixExplain,
			Steps:   []string{fmt.Sprintf("change %s's password; the password was right and the code was wrong %d times", u, n)},
			Inputs:  Digest([]any{u, n, t.Day}),
		})
	}
	return out
}
