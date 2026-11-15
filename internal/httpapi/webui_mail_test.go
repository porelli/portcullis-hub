package httpapi

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mailSection renders mysignin.js's mailHtml(view) under node (skipped
// without node outside CI).
func mailSection(t *testing.T, view any) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the Sign-in page tests")
		}
		t.Skip("node not installed")
	}
	v, _ := json.Marshal(view)
	script := "global.window = { addEventListener() {} };\n" + webAsset(t, "mysignin.js") +
		"\nprocess.stdout.write(window.PortcullisMySignIn.mailHtml(" + string(v) + "));\n"
	cmd := exec.Command(node, "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	return string(out)
}

// TestMySignInMailSection: the settings, the addresses, each password
// (Revoke for active, "reset by a restore" for voided, never a secret),
// labels escaped, Create hidden at 5 active.
func TestMySignInMailSection(t *testing.T) {
	view := map[string]any{"addresses": []string{"alice@example.org", "alice@team-b.example.net"}, "server": "mail.example.org",
		"imaps": 993, "submissions": 465, "submission": 587, "username": "alice@example.org",
		"passwords": []any{
			map[string]any{"id": "m1", "label": "iPhone <b>", "created_at": "2026-11-15T09:00:00Z", "expires_at": nil, "last_used": nil, "status": "active"},
			map[string]any{"id": "m2", "label": "Laptop", "created_at": "2026-11-01T09:00:00Z", "expires_at": "2027-11-01T09:00:00Z", "last_used": nil, "status": "voided"},
		}}
	h := mailSection(t, view)
	for _, want := range []string{"Mail passwords", "mail.example.org · port 993 · SSL/TLS", "port 465 · SSL/TLS (or 587 · STARTTLS)",
		"alice@team-b.example.net", "iPhone &lt;b&gt;", `data-msi-act="mail-revoke" data-mail-id="m1"`, "reset by a restore", "+ New mail password", `data-msi-panel="mail"`} {
		if !strings.Contains(h, want) {
			t.Errorf("section lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "iPhone <b>") || strings.Contains(h, `data-mail-id="m2"`) {
		t.Errorf("unescaped label or a revoke on a voided row:\n%s", h)
	}
	var five []any
	for i := 0; i < 5; i++ {
		five = append(five, map[string]any{"id": "x", "label": "d", "created_at": "2026-11-15T09:00:00Z", "status": "active"})
	}
	view["passwords"] = five
	if h := mailSection(t, view); strings.Contains(h, "+ New mail password") || !strings.Contains(h, "At most 5 mail passwords") {
		t.Errorf("five active:\n%s", h)
	}
}

// nodeEval runs script under node and answers stdout (skipped without
// node outside CI).
func nodeEval(t *testing.T, script string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the web UI tests")
		}
		t.Skip("node not installed")
	}
	cmd := exec.Command(node, "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	return string(out)
}

// TestSettingsMailPanel: Settings → Mail shows each domain with its
// state and the right button, the read-only facts, the drain warning,
// the DQS hint; mail off and Kubernetes show their texts; values are
// escaped.
func TestSettingsMailPanel(t *testing.T) {
	render := func(v, st any) string {
		vb, _ := json.Marshal(v)
		sb, _ := json.Marshal(st)
		return nodeEval(t, "global.window = {};\n"+webAsset(t, "mail.js")+"\nprocess.stdout.write(window.PortcullisMail.settingsHtml("+string(vb)+","+string(sb)+"));\n")
	}
	view := map[string]any{"mail": "on", "kubernetes": false, "hostname": "mail.example.org", "primary_domain": "example.org",
		"domains": []any{map[string]any{"name": "example.org", "enabled": true, "state": "on", "groups": []string{}},
			map[string]any{"name": "team-b.example.net", "enabled": false, "state": "draining", "groups": []string{"team_b<x>"}}},
		"spam":   map[string]any{"reject_score": 15, "junk_score": 5, "dnsbl": map[string]any{"spamhaus": true, "spamcop": false, "barracuda": true}, "allow": []string{"a.example"}, "block": []string{}},
		"limits": map[string]any{"recipients_per_hour": 300, "recipients_per_day": 1000}, "quotas": []any{map[string]any{"group": "team_b", "bytes": 21474836480}},
		"relay": "off", "submission_lan_only": false, "former_retention": "720h", "dqs_key": "not set"}
	h := render(view, map[string]any{"mail": "on", "reachable": true})
	for _, want := range []string{"mail.example.org", `data-mail-domain="team-b.example.net"`, "draining", `data-mail-act="domain-on"`, `data-mail-act="domain-off"`,
		"team_b&lt;x&gt;", "up to 7 days", "MAIL_SPAMHAUS_DQS_KEY", "team_b = 20", "reachable", `data-mail-dnsbl="spamcop">`} {
		if !strings.Contains(h, want) {
			t.Errorf("panel lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "team_b<x>") {
		t.Error("unescaped group")
	}
	if strings.Contains(h, "data-mail-lan-refusal") {
		t.Error("a LAN-only refusal without one")
	}
	view["submission_lan_only_refusal"] = "LAN-only needs the real client address; rootless Podman rewrites it"
	if h := render(view, nil); !strings.Contains(h, "data-mail-lan-refusal") || !strings.Contains(h, "rootless Podman rewrites it") {
		t.Errorf("podman refusal: %s", h)
	}
	view["mail"] = "off"
	if h := render(view, nil); !strings.Contains(h, "Mail is off: run ./portcullis mail enable on the host") {
		t.Errorf("off: %s", h)
	}
	view["kubernetes"] = true
	if h := render(view, nil); !strings.Contains(h, "available on Kubernetes yet") || strings.Contains(h, "data-mail-settings") {
		t.Errorf("kube: %s", h)
	}
}

// TestDirectoryMailSections: a person's Mail section (aliases editor for
// administrators only; Revoke per active password; no create) and the
// group's list form.
func TestDirectoryMailSections(t *testing.T) {
	v := map[string]any{"addresses": []string{"alice@example.org"}, "aliases": []string{"sales@example.org"},
		"passwords": []any{map[string]any{"id": "m1", "label": "Phone <1>", "created_at": "2026-11-15T09:00:00Z", "status": "active"},
			map[string]any{"id": "m2", "label": "Old", "created_at": "2026-11-01T09:00:00Z", "status": "voided"}}}
	vb, _ := json.Marshal(v)
	stub := "global.window = { addEventListener() {}, location: { hash: '' } }; global.document = { addEventListener() {}, querySelector() { return null; } }; global.location = window.location;\n"
	run := func(expr string) string {
		return nodeEval(t, stub+webAsset(t, "directory.js")+"\nprocess.stdout.write("+expr+");\n")
	}
	h := run("window.PortcullisDirectory._test.personMailHtml('alice', " + string(vb) + ", true)")
	for _, want := range []string{"alice@example.org", "data-pp-aliases", "sales@example.org", `data-act="mail-pw-revoke" data-user="alice" data-id="m1"`, "Phone &lt;1&gt;", "reset by a restore", "Only alice can create"} {
		if !strings.Contains(h, want) {
			t.Errorf("person section lacks %q:\n%s", want, h)
		}
	}
	if h := run("window.PortcullisDirectory._test.personMailHtml('alice', " + string(vb) + ", false)"); strings.Contains(h, "data-pp-aliases") {
		t.Errorf("a helper gets the aliases editor:\n%s", h)
	}
	g := run(`window.PortcullisDirectory._test.groupMailHtml('Team_B', {domains: [{name: 'example.org', state: 'on'}, {name: 'off.example', state: 'off'}], lists: []})`)
	if !strings.Contains(g, "team_b@&lt;domain&gt;") || !strings.Contains(g, `data-act="mail-list-on"`) || strings.Contains(g, "off.example") || strings.Contains(g, "mail-list-off") {
		t.Errorf("group form:\n%s", g)
	}
	g = run(`window.PortcullisDirectory._test.groupMailHtml('Team_B', {domains: [{name: 'example.org', state: 'on'}, {name: 'b.example', state: 'on'}], lists: [{group: 'Team_B', address: 'team_b@b.example', domain: 'b.example', posting: 'anyone'}]})`)
	if !strings.Contains(g, "data-gp-mail-current") || !strings.Contains(g, "team_b@b.example") || !strings.Contains(g, "anyone may post") ||
		!strings.Contains(g, `<option value="b.example" selected>`) || !strings.Contains(g, "Save the list") || !strings.Contains(g, "mail-list-off") {
		t.Errorf("current list:\n%s", g)
	}
}
