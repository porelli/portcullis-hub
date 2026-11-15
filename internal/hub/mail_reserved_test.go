package hub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// setCoreMail writes PORTCULLIS_MAIL into the fixture's core env.
func setCoreMail(t *testing.T, f *fixture, on bool) {
	t.Helper()
	v := "off"
	if on {
		v = "on"
	}
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_MAIL="+v+"\nPORTCULLIS_MAIL_HOSTNAME=mail.example.org\n")
}

// TestInstanceHostReservedForMail: mail.<e>, mta-sts.<e>, autoconfig.<e>
// and autodiscover.<e> are refused on a mail domain (on or draining), and
// free again once it is off; the main domain is a mail domain while core's
// mail profile is on, unless turned off.
func TestInstanceHostReservedForMail(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.test", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	set := func(host string) error {
		return f.h.SetHosts("grafana-b", map[string]string{"grafana": host}, directory.Human("alice"))
	}
	f.h.mu.Lock()
	f.h.st.Mail.Domains = map[string]state.MailDomain{"team-b.test": {Enabled: true}}
	f.h.mu.Unlock()
	for _, host := range []string{"mail.team-b.test", "mta-sts.team-b.test", "autoconfig.team-b.test", "Autodiscover.Team-B.test."} {
		err := set(host)
		want := "hostname " + NormalizeHost(host) + " is reserved for mail on team-b.test"
		if statusOf(err) != 409 || err.Error() != want {
			t.Errorf("%s: %v, want 409 %q", host, err, want)
		}
	}
	if err := set("grafana.team-b.test"); err != nil {
		t.Errorf("an ordinary host on a mail domain: %v", err)
	}
	// Draining still reserves; off frees.
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.test"] = state.MailDomain{Draining: true}
	f.h.mu.Unlock()
	if err := set("mail.team-b.test"); statusOf(err) != 409 {
		t.Errorf("draining: %v", err)
	}
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.test"] = state.MailDomain{}
	f.h.mu.Unlock()
	if err := set("mail.team-b.test"); err != nil {
		t.Errorf("mail off for team-b: %v", err)
	}

	// The main domain: free while core's mail is off, reserved while on,
	// free again when an admin turned the main domain off.
	if err := set("autoconfig.example.org"); err != nil {
		t.Errorf("core mail off: %v", err)
	}
	setCoreMail(t, f, true)
	if err := set("mta-sts.example.org"); statusOf(err) != 409 || !strings.Contains(err.Error(), "reserved for mail on example.org") {
		t.Errorf("core mail on, main domain: %v", err)
	}
	f.h.mu.Lock()
	f.h.st.Mail.Domains["example.org"] = state.MailDomain{}
	f.h.mu.Unlock()
	if err := set("mta-sts.example.org"); err != nil {
		t.Errorf("main domain turned off: %v", err)
	}
}

// TestInstanceSubdomainReservedForMail: a ${PORTCULLIS_DOMAIN} template
// (Subdomains) can't route mail.<main domain> either.
func TestInstanceSubdomainReservedForMail(t *testing.T) {
	f := newFixture(t)
	setCoreMail(t, f, true)
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	v := &templates.Template{ID: "x", Subdomains: []string{"mail"}}
	if err := f.h.checkInstanceHostsLocked(v, nil); statusOf(err) != 409 || err.Error() != "hostname mail.example.org is reserved for mail on example.org" {
		t.Fatalf("subdomain mail: %v", err)
	}
	v.Subdomains = []string{"webmail"}
	if err := f.h.checkInstanceHostsLocked(v, nil); err != nil {
		t.Fatalf("subdomain webmail: %v", err)
	}
}

// TestPortCollisionWithMail: no app may publish 25, 465, 587 or 993/tcp
// while PORTCULLIS_MAIL=on; any other port, or mail off, is fine.
func TestPortCollisionWithMail(t *testing.T) {
	f := newFixture(t)
	setPort := func(p string) {
		f.h.mu.Lock()
		s := f.h.st.Settings["grafana"]
		s.Ports = map[string]string{"GRAFANA_PORT": p}
		f.h.st.Settings["grafana"] = s
		f.h.mu.Unlock()
	}
	setPort("587")
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatalf("mail off: %v", err)
	}
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	setCoreMail(t, f, true)
	for _, p := range []string{"25", "465", "587", "993"} {
		setPort(p)
		err := f.h.Enable("grafana")
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "port 0.0.0.0:"+p+"/tcp is mail's") {
			t.Errorf("port %s: %v", p, err)
		}
	}
	setPort("2525")
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatalf("port 2525: %v", err)
	}
}

// TestCoreMailEnvNeverCopied: a template referencing PORTCULLIS_MAIL* (or
// PORTCULLIS_MAILCTL_*) never gets core's value (contract §2).
func TestCoreMailEnvNeverCopied(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_MAIL=on\nPORTCULLIS_MAIL_HOSTNAME=mail.example.org\nPORTCULLIS_MAILCTL_API_IP=172.31.255.19\n")
	compose := "services:\n  web:\n    image: grafana\n    environment:\n      X: ${CORE_VAR}\n      GF_THEME: ${GF_THEME:-dark}\n      M: ${PORTCULLIS_MAIL}\n      H: ${PORTCULLIS_MAIL_HOSTNAME}\n      I: ${PORTCULLIS_MAILCTL_API_IP}\n    labels:\n      traefik.http.routers.grafana.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-x}`)\n      traefik.http.routers.grafana.entrypoints: websecure\n"
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), compose)
	f.h.Discover()
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(f.h.envPath("grafana"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "CORE_VAR=core-value") {
		t.Fatalf("core var not copied:\n%s", env)
	}
	for _, k := range []string{"PORTCULLIS_MAIL=", "PORTCULLIS_MAIL_HOSTNAME", "PORTCULLIS_MAILCTL_API_IP", "172.31.255.19"} {
		if strings.Contains(string(env), k) {
			t.Errorf("%s copied into the app env:\n%s", k, env)
		}
	}
}
