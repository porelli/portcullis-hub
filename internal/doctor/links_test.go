package doctor

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestLinkRoute: a link's hash is built only from parts that validate;
// anything else drops the link (contract §14.5 "Links").
func TestLinkRoute(t *testing.T) {
	cases := []struct {
		l    Link
		want string
	}{
		{Link{Instance: "stalwart", Tab: "mail"}, "#apps/stalwart/mail"},
		{Link{Instance: "grafana-team-a", Option: "smtp_host"}, "#apps/grafana-team-a/settings/smtp_host"},
		{Link{Instance: "grafana", Tab: "settings", Option: "a.b-c"}, "#apps/grafana/settings/a.b-c"},
		{Link{Instance: "grafana"}, "#apps/grafana"},
		{Link{Instance: "grafana", Tab: "overview"}, "#apps/grafana"},
		{Link{Instance: "aiapp", Tab: TabAI}, "#apps/aiapp/ai"},
		{Link{Page: PageSettingsMail}, "#settings/mail"},
		{Link{Page: PageAccessSSHHosts}, "#access/ssh/hosts"},
		{Link{Page: PageUsageStorage}, "#usage/storage"},
		// Refused: every one drops the link.
		{Link{Instance: "Grafana", Tab: "mail"}, ""},
		{Link{Instance: "a/../b"}, ""},
		{Link{Instance: "x\" onclick=\"y"}, ""},
		{Link{Instance: "javascript:alert(1)"}, ""},
		{Link{Instance: "grafana", Tab: "bogus"}, ""},
		{Link{Instance: "grafana", Tab: "logs", Option: "x"}, ""},
		{Link{Instance: "grafana", Option: "a<b"}, ""},
		{Link{Instance: "grafana", Option: "a/b"}, ""},
		{Link{Page: "settings/domains"}, ""},
		{Link{Page: "//evil.example/"}, ""},
		{Link{Page: PageSettingsMail, Instance: "grafana"}, ""},
		{Link{}, ""},
	}
	for _, c := range cases {
		if got := c.l.Route(); got != c.want {
			t.Errorf("%+v → %q, want %q", c.l, got, c.want)
		}
	}
}

// TestDefaultLinks: the per-kind table, and Run filling hash (a check's
// own link kept, an invalid one dropped).
func TestDefaultLinks(t *testing.T) {
	cases := []struct {
		f    Finding
		want string
	}{
		{Finding{Kind: KindMailPTRMissing}, "#settings/mail"},
		{Finding{Kind: KindMailProviderMissing}, "#settings/mail"},
		{Finding{Kind: KindMailProviderRefused}, "#settings/mail"}, // no instance named
		{Finding{Kind: KindDNSRecordsWrong}, "#settings/network"},
		{Finding{Kind: KindDNSSECBogus}, "#settings/network"},
		{Finding{Kind: KindLocalNetworksEmpty}, "#settings/network"},
		{Finding{Kind: KindVPNDown}, "#settings/network"},
		{Finding{Kind: KindVPNProviderStale, Instances: []string{"mesh"}}, "#apps/mesh/vpn"},
		{Finding{Kind: KindVPNProviderStale, Instances: []string{"a", "b"}}, "#settings/network"},
		{Finding{Kind: KindVPNExpiring}, "#access/vpn"},
		{Finding{Kind: KindGIDCollision}, "#settings/storage"},
		{Finding{Kind: KindFolderOwner}, "#settings/storage"},
		{Finding{Kind: KindCredentialWithoutAccess, Instances: []string{"samba"}}, "#apps/samba/filesharing"},
		{Finding{Kind: KindCredentialWithoutAccess}, ""},
		{Finding{Kind: KindServerOffline}, "#settings/servers"},
		{Finding{Kind: KindInstanceQuarantined, Instances: []string{"paperless"}}, "#apps/paperless"},
		{Finding{Kind: KindInstanceOrphaned}, "#settings/servers"},
		{Finding{Kind: KindSSHCAMissing}, "#settings/ssh"},
		{Finding{Kind: KindSSHHostDrift}, "#access/ssh/hosts"},
		{Finding{Kind: KindSSHHostGroupUnused}, "#access/ssh/hostgroups"},
		{Finding{Kind: KindSSHPrivilegedGrant}, "#access/ssh/grants"},
		{Finding{Kind: KindSSHBreakglassUsed}, "#access/ssh/certs"},
		{Finding{Kind: KindSignInTOTPPolicyDrift}, "#settings/signin"},
		{Finding{Kind: KindSignInFIDOUnavailable}, "#settings/signin"},
		{Finding{Kind: KindSignInTOTPGuessing}, ""},
		{Finding{Kind: KindDiskNearlyFull}, "#usage/storage"},
		{Finding{Kind: KindUsageNotMeasured}, "#usage"},
		{Finding{Kind: KindCustomOverrideMount, Instances: []string{"immich"}}, "#apps/immich/expert"},
		{Finding{Kind: KindLANOnlyExposed, Instances: []string{"samba"}}, "#apps/samba/settings"},
		{Finding{Kind: KindRuntimeMismatch}, ""},
		// A check's own link wins over the table, and gets its hash.
		{Finding{Kind: KindMemoryNearLimit, Link: &Link{Instance: "gitea", Tab: TabUsage}}, "#apps/gitea/usage"},
		{Finding{Kind: KindDiskNearlyFull, Link: &Link{Instance: "gitea", Tab: TabUsage}}, "#apps/gitea/usage"},
		// An invalid check link is dropped, never replaced.
		{Finding{Kind: KindDiskNearlyFull, Link: &Link{Instance: "Bad id"}}, ""},
	}
	for _, c := range cases {
		f := c.f
		finishLink(&f)
		got := ""
		if f.Link != nil {
			got = f.Link.Hash
		}
		if got != c.want {
			t.Errorf("%s %v → %q, want %q", c.f.Kind, c.f.Instances, got, c.want)
		}
	}
}

// TestMailProviderRefusedLink: mail_provider_refused (and the provider's
// other findings) open the wired provider's Mail tab, through Run.
func TestMailProviderRefusedLink(t *testing.T) {
	fs := mailRun(&MailIn{Wired: true, Instance: "stalwart", Main: "example.org", Refused: "the mail provider's template changed"})
	if len(fs) != 1 || fs[0].Kind != KindMailProviderRefused || fs[0].Link == nil || fs[0].Link.Instance != "stalwart" || fs[0].Link.Tab != "mail" {
		t.Fatalf("findings = %+v", fs)
	}
	r := Run(&Inputs{Now: mailNow, Mail: &MailIn{Wired: true, Instance: "stalwart", Main: "example.org", Refused: "changed"}}, nil)
	for _, f := range r.Findings {
		if f.Kind == KindMailProviderRefused {
			if f.Link == nil || f.Link.Hash != "#apps/stalwart/mail" {
				t.Errorf("link = %+v", f.Link)
			}
			return
		}
	}
	t.Fatal("no mail_provider_refused finding in the report")
}

// TestEveryLinkHashShape: every hash Run can build is one of the shapes
// the Hub UI accepts (web/doctor.js LINK_RE, the same pattern).
func TestEveryLinkHashShape(t *testing.T) {
	re := regexp.MustCompile(LinkHashPattern)
	for p := range linkPages {
		if h := (Link{Page: p}).Route(); !re.MatchString(h) {
			t.Errorf("page %s → %q doesn't match %s", p, h, LinkHashPattern)
		}
	}
	for tab := range linkTabs {
		if h := (Link{Instance: "a-b1", Tab: tab}).Route(); !re.MatchString(h) {
			t.Errorf("tab %s → %q doesn't match", tab, h)
		}
	}
	if h := (Link{Instance: "a", Option: "x_y.z-1"}).Route(); !re.MatchString(h) {
		t.Errorf("option → %q doesn't match", h)
	}
	for _, bad := range []string{"#apps/A", "#apps/a/settings/<x>", "#settings/domains", "javascript:x", "#apps/a/b/c/d", "https://x/#apps/a"} {
		if re.MatchString(bad) {
			t.Errorf("%q matches the UI pattern", bad)
		}
	}
}

// TestEveryKindHasALinkOrNone: every kind this package defines gets a
// default link, or is one of the kinds whose fix lives on no Hub page
// (host-level, a person's own). A new kind must pick one (contract
// §14.5 "Links").
func TestEveryKindHasALinkOrNone(t *testing.T) {
	noPage := map[string]bool{
		// The engine, the host, the Kubernetes cluster.
		KindRuntimeMismatch: true, KindLimitsNotEnforced: true, KindSELinuxLabelMissing: true, KindUDPSourceRewritten: true,
		KindNetpolNotEnforced: true, KindAdmissionGuardMissing: true, KindClusterUnverified: true, KindKubeAPIPublic: true,
		// One person's (the people page, not the Hub).
		KindSignInTOTPGuessing: true, KindSSHUsernameCollision: true,
	}
	re := regexp.MustCompile(`Kind[A-Za-z0-9]+\s*=\s*"([a-z0-9_]+)"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			kinds[m[1]] = true
		}
	}
	if len(kinds) < 130 {
		t.Fatalf("only %d kinds found: the scan is broken", len(kinds))
	}
	for k := range kinds {
		f := Finding{Kind: k, Instances: []string{"app"}}
		got := defaultLink(&f)
		switch {
		case noPage[k] && got != nil:
			t.Errorf("%s has a link %+v but is listed as having no page", k, got)
		case !noPage[k] && got == nil:
			t.Errorf("%s has no default link: add it to defaultLink, or to noPage with the reason", k)
		case got != nil && got.Route() == "":
			t.Errorf("%s's default link %+v doesn't validate", k, got)
		}
	}
}
