package doctor

import (
	"strings"
	"testing"
)

// TestDoctorTOTPDrift (T12): a realm OTP setting that differs is a
// Problem naming it, explain-only with the configure step; none, or no
// input, nothing.
func TestDoctorTOTPDrift(t *testing.T) {
	for _, in := range []*Inputs{{}, {SignInTOTP: &SignInTOTPIn{Day: "2026-11-14"}}} {
		if got := of(t, KindSignInTOTPPolicyDrift, in); len(got) != 0 {
			t.Errorf("fine: %+v", got)
		}
	}
	got := of(t, KindSignInTOTPPolicyDrift, &Inputs{SignInTOTP: &SignInTOTPIn{PolicyDrift: []string{"otpPolicyDigits"}, Day: "2026-11-14"}})
	if len(got) != 1 || got[0].Severity != Problem || got[0].Class != FixExplain || !strings.Contains(got[0].Why, "otpPolicyDigits") ||
		len(got[0].Steps) == 0 || !strings.Contains(strings.Join(got[0].Steps, " "), "./portcullis keycloak configure") {
		t.Fatalf("drift: %+v", got)
	}
	two := of(t, KindSignInTOTPPolicyDrift, &Inputs{SignInTOTP: &SignInTOTPIn{PolicyDrift: []string{"otpPolicyDigits", "otpPolicyPeriod"}}})
	if len(two) != 1 || !strings.Contains(two[0].Why, "otpPolicyPeriod") || two[0].FP != got[0].FP || two[0].Inputs == got[0].Inputs {
		t.Errorf("two settings: %+v", two)
	}
}

// TestDoctorTOTPGuessing (T12): 20 wrong codes in 24 h for a person is a
// Warning (19 isn't), one per person per day.
func TestDoctorTOTPGuessing(t *testing.T) {
	in := &Inputs{SignInTOTP: &SignInTOTPIn{Wrong: map[string]int{"alice": 19, "bob": 20, "carol": 41}, Day: "2026-11-14"}}
	got := of(t, KindSignInTOTPGuessing, in)
	if len(got) != 2 {
		t.Fatalf("findings: %+v", got)
	}
	by := map[string]Finding{}
	for _, f := range got {
		if len(f.Persons) != 1 {
			t.Fatalf("persons: %+v", f)
		}
		by[f.Persons[0]] = f
	}
	b := by["bob"]
	if b.Severity != Warning || b.Class != FixExplain || b.FP != Fingerprint(KindSignInTOTPGuessing, "bob", "2026-11-14") ||
		!strings.Contains(strings.Join(b.Steps, " "), "change bob's password; the password was right and the code was wrong 20 times") {
		t.Errorf("bob = %+v", b)
	}
	if c := by["carol"]; !strings.Contains(strings.Join(c.Steps, " "), "41 times") || c.FP == b.FP {
		t.Errorf("carol = %+v", c)
	}
	// Another day: another fingerprint.
	in.SignInTOTP.Day = "2026-11-15"
	if next := of(t, KindSignInTOTPGuessing, in); next[0].FP == got[0].FP && next[1].FP == got[1].FP {
		t.Error("the fingerprint ignores the day")
	}
	if got := of(t, KindSignInTOTPGuessing, &Inputs{SignInTOTP: &SignInTOTPIn{Day: "2026-11-14"}}); len(got) != 0 {
		t.Errorf("unknown counts: %+v", got)
	}
}

// TestDoctorTOTPCapped (review M1): over the 1,000-event cap the counts
// still judge (a lower bound: 20 or more is still a Warning), and an Info
// says the read was capped, once per day.
func TestDoctorTOTPCapped(t *testing.T) {
	in := &Inputs{SignInTOTP: &SignInTOTPIn{Wrong: map[string]int{"bob": 25}, Capped: true, Day: "2026-11-14"}}
	if got := of(t, KindSignInTOTPGuessing, in); len(got) != 1 || got[0].Severity != Warning || got[0].Persons[0] != "bob" {
		t.Errorf("guessing under the cap: %+v", got)
	}
	got := of(t, KindSignInLoginErrorsCapped, in)
	if len(got) != 1 || got[0].Severity != Info || got[0].Title != "LOGIN_ERROR read capped at 1,000 events: counts are lower bounds" ||
		got[0].FP != Fingerprint(KindSignInLoginErrorsCapped, "2026-11-14") {
		t.Fatalf("capped: %+v", got)
	}
	in.SignInTOTP.Capped = false
	if got := of(t, KindSignInLoginErrorsCapped, in); len(got) != 0 {
		t.Errorf("not capped: %+v", got)
	}
	if got := of(t, KindSignInLoginErrorsCapped, &Inputs{}); len(got) != 0 {
		t.Errorf("no input: %+v", got)
	}
}
