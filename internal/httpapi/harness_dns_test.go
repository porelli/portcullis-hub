//go:build harness

package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/domains"
)

// seedDomains gives the harness a fake domains service (DNS hardening
// Task 11): team-b.example.net added (cloudflare, ready) with a plan that
// has every kind of row — address ok, a CAA missing (Fix), another CA's
// entry, a nomail recommendation, a dangling CNAME, an unsigned zone the
// provider can sign — and a main-domain plan with a DS to copy.
func seedDomains(t *testing.T, e *instEnv) {
	secret := strings.Repeat("d", 40)
	fake, fsrv := newFakeDomainsService(t, secret)
	sf := filepath.Join(t.TempDir(), "api-secret")
	os.WriteFile(sf, []byte(secret+"\n"), 0600)
	d := "team-b.example.net"
	fake.mu.Lock()
	fake.list[d] = map[string]any{"name": d, "provider": "cloudflare", "records_ok": true, "cert_not_after": "2027-02-01T00:00:00Z",
		"last_error": "", "state": "ready", "caa_ok": false, "dnssec": "unsigned"}
	ours := `0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"`
	oursWild := `0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"`
	fake.plans = map[string]map[string]any{
		d: {"name": d, "checked_at": "2026-11-13T09:12:44Z", "can_write": true,
			"items": []map[string]any{
				{"set": "address", "name": d, "type": "A", "want": []string{"203.0.113.10"}, "live": []string{"203.0.113.10"}, "status": "ok", "severity": "ok", "fix": "none", "steps": []string{}},
				{"set": "address", "name": "*." + d, "type": "A", "want": []string{"203.0.113.10"}, "live": []string{"203.0.113.10"}, "status": "ok", "severity": "ok", "fix": "none", "steps": []string{}},
				{"set": "caa", "name": d, "type": "CAA", "want": []string{`0 issue "digicert.com"`, ours, oursWild}, "live": []string{`0 issue "digicert.com"`},
					"status": "missing", "severity": "warning", "fix": "auto", "steps": []string{"add CAA " + d + " " + ours + " (TTL 300)", "add CAA " + d + " " + oursWild + " (TTL 300)"}},
				{"set": "caa", "name": d, "type": "CAA", "want": []string{}, "live": []string{}, "status": "foreign", "severity": "info", "fix": "none",
					"steps": []string{"other CAs may also issue for " + d + ": digicert.com", "writing issuewild takes wildcard issuance for *." + d + " away from digicert.com"}},
				{"set": "nomail", "name": d, "type": "MX", "want": []string{"0 ."}, "live": []string{}, "status": "missing", "severity": "info", "fix": "auto",
					"steps": []string{d + " has no MX and no SPF: publishing the nomail set (null MX, SPF -all, DMARC reject) stops others sending mail as it"}},
				{"set": "address", "name": "old." + d, "type": "CNAME", "want": []string{}, "live": []string{"gone.example.com."}, "status": "foreign", "severity": "warning", "fix": "manual",
					"steps": []string{"remove the dangling CNAME old." + d + " → gone.example.com (the target doesn't exist)"}},
			},
			"caa":    map[string]any{"issuer": "letsencrypt.org", "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123", "would_issue": false},
			"dnssec": map[string]any{"state": "unsigned", "zone": "example.net", "provider_can_sign": true, "ds": []any{}, "steps": []string{"Turn on signing at cloudflare (one click: it signs the whole zone example.net), then add the DS it shows at your registrar"}}},
		"": {"name": "example.org", "checked_at": "2026-11-13T09:10:02Z", "can_write": false,
			"items": []map[string]any{
				{"set": "address", "name": "example.org", "type": "A", "want": []string{"203.0.113.10"}, "live": []string{"203.0.113.10"}, "status": "ok", "severity": "ok", "fix": "none", "steps": []string{}},
				{"set": "caa", "name": "example.org", "type": "CAA", "want": []string{ours}, "live": []string{ours}, "status": "ok", "severity": "ok", "fix": "none", "steps": []string{}},
			},
			"caa": map[string]any{"issuer": "letsencrypt.org", "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123", "would_issue": true},
			"dnssec": map[string]any{"state": "ds_missing", "zone": "example.org", "provider_can_sign": false,
				"ds":    []map[string]any{{"key_tag": 2371, "algorithm": 13, "digest_type": 2, "digest": "1F987CC6583E92DF0890718C42E9E4F2E1C9C4A1F3E2B7C8D9E0A1B2C3D4E5F6"}},
				"steps": []string{"Add this DS at your registrar: key tag 2371, algorithm 13, digest type 2, digest 1F987CC6583E92DF0890718C42E9E4F2E1C9C4A1F3E2B7C8D9E0A1B2C3D4E5F6"}}},
	}
	fake.mu.Unlock()
	e.s.Hub.SetDomainsAPI(domains.New(fsrv.URL, sf))
	if _, err := e.s.Hub.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
}
