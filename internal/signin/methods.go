// Package signin is the Hub's model of sign-in methods and templates
// (contract §8.1): the method table, rule trees, compiling a rule against the
// switched-on methods, evaluating compiled rules, scores and the plain-English
// sentence. It is pure: no I/O and no state beyond the fixed tables.
package signin

// Method is a sign-in method id.
type Method string

// The six methods (D1).
const (
	Password      Method = "password"
	PasskeySynced Method = "passkey_synced"
	BrowserCert   Method = "browser_cert"
	PasskeyDevice Method = "passkey_device"
	SecurityKey   Method = "security_key"
	YubiKeyCert   Method = "yubikey_cert"
)

// Methods lists every method in canonical order (weakest first).
var Methods = []Method{Password, PasskeySynced, BrowserCert, PasskeyDevice, SecurityKey, YubiKeyCert}

// Info describes a method. Label is the Settings name, Short the name used
// in "<Short> + <Short> only" warnings, Phrase the rule sentence's words,
// AMR the value Keycloak records, Tenths the strength in tenths.
// Available is false for a method that can't be switched on yet (since
// sign-in part 2 every method can be).
type Info struct {
	ID        Method
	Label     string
	Short     string
	Phrase    string
	AMR       string
	Tenths    int
	Available bool
}

var methodInfo = map[Method]Info{
	Password:      {Password, "Password", "password", "a password", "pwd", 10, true},
	PasskeySynced: {PasskeySynced, "Synced passkey", "synced passkey", "a synced passkey", "spk", 25, true},
	BrowserCert:   {BrowserCert, "Browser certificate", "browser certificate", "a browser certificate", "file", 25, true},
	PasskeyDevice: {PasskeyDevice, "Device-bound passkey", "device-bound passkey", "a device-bound passkey", "dpk", 30, true},
	SecurityKey:   {SecurityKey, "Security key", "security key", "a YubiKey touch", "hwk", 35, true},
	YubiKeyCert:   {YubiKeyCert, "YubiKey certificate", "YubiKey certificate", "a YubiKey certificate", "mtls", 40, true},
}

// InfoOf returns the table entry of m.
func InfoOf(m Method) (Info, bool) {
	i, ok := methodInfo[m]
	return i, ok
}

// MethodForAMR maps an amr value to its method. "inv" (a setup-link
// session) and every value outside the table map to nothing.
func MethodForAMR(amr string) (Method, bool) {
	for _, m := range Methods {
		if methodInfo[m].AMR == amr {
			return m, true
		}
	}
	return "", false
}

// rank is m's canonical position, -1 for an unknown id.
func rank(m Method) int {
	for i, x := range Methods {
		if x == m {
			return i
		}
	}
	return -1
}

// family is a leaf naming several methods at once. No family contains
// password.
type family struct {
	members []Method
	phrase  string
}

var families = map[string]family{
	"family:passkey":     {[]Method{PasskeySynced, PasskeyDevice, SecurityKey}, "a passkey"},
	"family:yubikey":     {[]Method{SecurityKey, YubiKeyCert}, "a YubiKey"},
	"family:certificate": {[]Method{YubiKeyCert, BrowserCert}, "a certificate"},
}

// isOn reports whether m counts as switched on: on says so and the method
// is available (a method that can't be switched on yet is off whatever on
// says).
func isOn(on map[Method]bool, m Method) bool {
	return on[m] && methodInfo[m].Available
}

// onMembers is f's switched-on members, in the family's order.
func (f family) onMembers(on map[Method]bool) []Method {
	var out []Method
	for _, m := range f.members {
		if isOn(on, m) {
			out = append(out, m)
		}
	}
	return out
}
