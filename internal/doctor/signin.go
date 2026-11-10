package doctor

import "fmt"

// Sign-in checks (contract §8.1 "FIDO metadata (Hub)", sign-in Task 8):
// the FIDO list the Keycloak extension classifies passkeys against.

// SignInMDSIn is the FIDO list's state when the Hub has none to publish:
// no BLOB loaded and the last load or refresh failed (nil = fine, or not
// fetching at all). Err is that failure; HighWaterFile is set when the
// cause is the high-water serial's file (it can't be read).
type SignInMDSIn struct {
	Err           string
	HighWaterFile string
}

// KindSignInFIDOUnavailable: no FIDO list.
const KindSignInFIDOUnavailable = "signin_fido_list_unavailable"

func init() { Register(signInFIDOCheck{}) }

type signInFIDOCheck struct{}

func (signInFIDOCheck) Kind() string { return KindSignInFIDOUnavailable }

func (signInFIDOCheck) Run(in *Inputs) []Finding {
	m := in.SignInMDS
	if m == nil {
		return nil
	}
	f := Finding{
		FP: Fingerprint(KindSignInFIDOUnavailable), Kind: KindSignInFIDOUnavailable, Severity: Warning,
		Title:  "The Hub has no FIDO list, so new passkeys count as synced passkeys.",
		Why:    fmt.Sprintf("The Hub couldn't load or fetch the FIDO Alliance's list of authenticators (%s). Without it the Keycloak extension can't tell security keys and device-bound passkeys apart: every new passkey registers as a synced one until the list loads.", m.Err),
		Class:  FixExplain,
		Inputs: Digest([]string{m.Err, m.HighWaterFile}),
	}
	if m.HighWaterFile != "" {
		f.Steps = []string{
			fmt.Sprintf("The file %s on the Hub's data volume can't be read. It holds one number: the highest FIDO list serial the Hub has accepted (it stops an older list being replayed).", m.HighWaterFile),
			"Fix its permissions (owned by the Hub, mode 0600) or its contents (that one number); the Hub refuses every FIDO list until it reads it.",
		}
	} else {
		f.Steps = []string{
			"Check that the Hub can reach the FIDO list's address (HUB_FIDO_MDS_URL, https://mds3.fidoalliance.org/ by default) and read the Hub's log for the error.",
			"The Hub retries every hour; nothing else is needed once it can fetch the list.",
		}
	}
	return []Finding{f}
}
