package doctor

import (
	"strings"
	"testing"
)

func TestSignInFIDOUnavailable(t *testing.T) {
	if got := of(t, KindSignInFIDOUnavailable, &Inputs{}); len(got) != 0 {
		t.Errorf("fine: %+v", got)
	}
	got := of(t, KindSignInFIDOUnavailable, &Inputs{SignInMDS: &SignInMDSIn{Err: "fido mds: fetch: status 500"}})
	if len(got) != 1 || got[0].Severity != Warning || got[0].Class != FixExplain || !strings.Contains(got[0].Why, "status 500") ||
		strings.Contains(strings.Join(got[0].Steps, " "), "mds.serial") {
		t.Fatalf("fetch failure: %+v", got)
	}
	hw := "/data/signin/mds.serial"
	got = of(t, KindSignInFIDOUnavailable, &Inputs{SignInMDS: &SignInMDSIn{Err: "high-water", HighWaterFile: hw}})
	if len(got) != 1 || !strings.Contains(strings.Join(got[0].Steps, " "), hw) {
		t.Fatalf("high-water: %+v", got)
	}
}
