package httpapi

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/hub"
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
	// Signed in as someone else: no create, no revoke.
	vb, _ := json.Marshal(view)
	ro := nodeEval(t, "global.window = { addEventListener() {} };\n"+webAsset(t, "mysignin.js")+"\nprocess.stdout.write(window.PortcullisMySignIn.mailHtml("+string(vb)+", true));\n")
	if strings.Contains(ro, "mail-create") || strings.Contains(ro, "mail-revoke") || !strings.Contains(ro, "Read-only while you are signed in as someone else") {
		t.Errorf("read-only:\n%s", ro)
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
		"relay": nil, "submission_lan_only": false, "dkim_rotate": "4320h", "former_retention": "720h"}
	h := render(view, map[string]any{"mail": "on", "reachable": true})
	for _, want := range []string{"mail.example.org", `data-mail-domain="team-b.example.net"`, "draining", `data-mail-act="domain-on"`, `data-mail-act="domain-off"`,
		"team_b&lt;x&gt;", "up to 7 days", "none (direct delivery)", "4320h", "team_b = 20", "reachable", `data-mail-dnsbl="spamcop">`} {
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
	view["pending_removal"] = map[string]any{"since": "2026-11-15T09:00:00Z", "confirmed": false, "confirm_phrase": "remove 2 mailboxes",
		"accounts": []any{map[string]any{"username": "alice", "uuid": "u-1", "revoked": true}, map[string]any{"username": "bob<x>", "uuid": "u-2", "revoked": false}}}
	if h := render(view, nil); !strings.Contains(h, "data-mail-pending") || !strings.Contains(h, `data-mail-uuids="u-1,u-2"`) || !strings.Contains(h, "bob&lt;x&gt; (revoking failed: retrying)") ||
		!strings.Contains(h, "alice (mail passwords revoked)") || !strings.Contains(h, "data-mail-removal-phrase") || !strings.Contains(h, `data-mail-phrase="remove 2 mailboxes"`) {
		t.Errorf("pending removal: %s", h)
	}
	view["problem"] = "Mail can't be managed: the Hub's mail secret is missing or too short"
	if h := render(view, nil); !strings.Contains(h, "data-mail-problem") || !strings.Contains(h, `data-mail-act="retry-void"`) {
		t.Errorf("secret problem: %s", h)
	}
	view["problem"] = nil
	view["pending_removal"] = nil
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
			map[string]any{"id": "m2", "label": "Old", "created_at": "2026-11-01T09:00:00Z", "status": "voided"},
			map[string]any{"id": "m3", "label": "Tablet", "created_at": "2026-11-01T09:00:00Z", "status": "unconfirmed"}}}
	vb, _ := json.Marshal(v)
	stub := "global.window = { addEventListener() {}, location: { hash: '' } }; global.document = { addEventListener() {}, querySelector() { return null; } }; global.location = window.location;\n"
	run := func(expr string) string {
		return nodeEval(t, stub+webAsset(t, "directory.js")+"\nprocess.stdout.write("+expr+");\n")
	}
	h := run("window.PortcullisDirectory._test.personMailHtml('alice', " + string(vb) + ", true)")
	for _, want := range []string{"alice@example.org", "data-pp-aliases", "sales@example.org", `data-act="mail-pw-revoke" data-user="alice" data-id="m1"`, "Phone &lt;1&gt;", "reset by a restore", "Only alice can create",
		"not confirmed: the mail server can't be read", `data-id="m3"`} {
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

// TestWebMailStates (T15): Settings → Mail's three slot states by id
// (closed, none with the Marketplace link and the installed mail
// instances, wired with Switch…, Unwire… and Retry), the Mail tab's
// warning node filled with exactly hub.MailWarning, and no provider text
// ever put into innerHTML.
func TestWebMailStates(t *testing.T) {
	view := map[string]any{"mail": "on", "kubernetes": false, "hostname": "mail.example.org", "domains": []any{}, "spam": map[string]any{}, "limits": map[string]any{}}
	state := func(v, st, insts any) string {
		vb, _ := json.Marshal(v)
		sb, _ := json.Marshal(st)
		ib, _ := json.Marshal(insts)
		return nodeEval(t, "global.window = {};\n"+webAsset(t, "mail.js")+"\nprocess.stdout.write(window.PortcullisMail.stateHtml("+string(vb)+","+string(sb)+","+string(ib)+"));\n")
	}
	if h := state(map[string]any{"mail": "off"}, nil, nil); !strings.Contains(h, `data-mail-state="closed"`) {
		t.Errorf("closed: %s", h)
	}
	h := state(view, map[string]any{"mail": "on", "provider": nil}, []any{map[string]any{"id": "stalwart", "label": "Mail<x>"}})
	if !strings.Contains(h, `data-mail-state="none"`) || !strings.Contains(h, `href="#marketplace?filter=mail"`) || !strings.Contains(h, `href="#apps/stalwart/mail"`) || strings.Contains(h, "Mail<x>") {
		t.Errorf("none: %s", h)
	}
	prov := map[string]any{"instance": "stalwart", "template": "stalwart", "label": "<img src=x onerror=alert(1)>", "version": "<b>1</b>", "mode": "void",
		"void": map[string]any{"reason": "restore", "since": "2026-11-17T00:00:00Z", "error": "<script>"}}
	h = state(view, map[string]any{"mail": "on", "provider": prov}, nil)
	for _, want := range []string{`data-mail-state="wired"`, `data-mail-act="switch"`, `data-mail-act="unwire"`, `data-mail-act="retry-void"`, `href="#apps/stalwart/mail"`} {
		if !strings.Contains(h, want) {
			t.Errorf("wired lacks %q: %s", want, h)
		}
	}
	if strings.Contains(h, "<img") || strings.Contains(h, "<b>1") || strings.Contains(h, "<script>") {
		t.Errorf("provider text in the markup: %s", h)
	}
	// The Mail tab: provider text never in the skeleton; the warning
	// node gets exactly MailWarning (by textContent, under a fake DOM).
	tv := map[string]any{"wired": true, "mode": "normal", "warning": hub.MailWarning, "provider": map[string]any{"name": "<i>S</i>", "version": "1", "checks": []string{}},
		"refused_because": []string{"<u>no</u>"}, "held": map[string]any{"reason": "<em>held</em>"}, "hold_warning": "w", "void": nil}
	tb, _ := json.Marshal(tv)
	out := nodeEval(t, `
const nodes = {};
function node(sel) { return nodes[sel] || (nodes[sel] = { textContent: '', children: [], appendChild(c) { this.children.push(c); } }); }
global.document = { createElement() { return { textContent: '' }; } };
global.window = {};
`+webAsset(t, "mailprovider.js")+`
const v = `+string(tb)+`;
const skel = window.PortcullisMailProvider.tabSkeleton(v);
window.PortcullisMailProvider.fillTab({ querySelector: node }, v);
process.stdout.write(JSON.stringify({ skel, warning: node('[data-mail-warning]').textContent, refused: node('[data-mail-refused]').children.map(c => c.textContent), info: node('[data-mail-provider-info]').textContent }));
`)
	var got struct {
		Skel, Warning, Info string
		Refused             []string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.Warning != hub.MailWarning || len(got.Refused) != 1 || got.Refused[0] != "<u>no</u>" || !strings.Contains(got.Info, "<i>S</i>") {
		t.Fatalf("%+v", got)
	}
	for _, bad := range []string{"<i>S", "<u>no", "<em>held", hub.MailWarning} {
		if strings.Contains(got.Skel, bad) {
			t.Errorf("%q in the skeleton's markup", bad)
		}
	}
	// No innerHTML assignment in mailprovider.js carries a view field.
	src := webAsset(t, "mailprovider.js")
	for _, ln := range strings.Split(src, "\n") {
		if strings.Contains(ln, "innerHTML") && (strings.Contains(ln, "v.provider") || strings.Contains(ln, "v.warning") || strings.Contains(ln, "refused_because") || strings.Contains(ln, "e.message")) {
			t.Errorf("provider text into innerHTML: %s", ln)
		}
	}
	// The Mail tab and the Marketplace filter are wired into the page.
	idx := webAsset(t, "index.html")
	for _, want := range []string{"['mail', 'Mail']", "templateIsMailProvider", "/static/mailprovider.js", "[/^marketplace(?:\\?filter=([a-z0-9-]{1,63}))?$/"} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// The Marketplace (marketplace.js): the mail badge, and the filter
	// pre-selects a category chip.
	for _, want := range []string{"'data-mail-badge'", "if (o && o.filter) st.cat = o.filter;"} {
		if !strings.Contains(webAsset(t, "marketplace.js"), want) {
			t.Errorf("marketplace.js lacks %q", want)
		}
	}
}

// TestWebMailSensitiveAndFormer (T28 gaps 1–3): the relay, DKIM rotation
// and former retention form (password write-only, a fresh sign-in on
// save), the former accounts read-only with the export hint, the
// provider pill and the secret banner's Retry.
func TestWebMailSensitiveAndFormer(t *testing.T) {
	render := func(v, st any) string {
		vb, _ := json.Marshal(v)
		sb, _ := json.Marshal(st)
		return nodeEval(t, "global.window = {};\n"+webAsset(t, "mail.js")+"\nprocess.stdout.write(window.PortcullisMail.settingsHtml("+string(vb)+","+string(sb)+",[]));\n")
	}
	view := map[string]any{"mail": "on", "hostname": "mail.example.org", "domains": []any{}, "spam": map[string]any{}, "limits": map[string]any{},
		"relay":       map[string]any{"host": "smtp.relay.example.net", "port": 587, "username": "u", "spf_include": "", "password_set": true},
		"dkim_rotate": "4320h", "former_retention": "720h", "problem": "Mail can't be managed: x"}
	st := map[string]any{"mail": "on", "reachable": false, "provider": nil,
		"status": map[string]any{"former": []any{map[string]any{"id": "f1", "username": "bob<x>", "since": "2026-11-01T00:00:00Z"}}}}
	h := render(view, st)
	for _, want := range []string{`data-mail-sensitive`, `data-mail-act="sensitive-save"`, `type="password"`, `placeholder="unchanged (set)"`, `value="4320h"`,
		`data-mail-former-list`, `bob&lt;x&gt;`, `./portcullis mail export &lt;id&gt;`, "mail provider unreachable", `data-mail-act="retry-void"`, "A fresh sign-in"} {
		if !strings.Contains(h, want) {
			t.Errorf("lacks %q", want)
		}
	}
	for _, bad := range []string{"mailctl unreachable", "./portcullis up", "bob<x>"} {
		if strings.Contains(h, bad) {
			t.Errorf("has %q", bad)
		}
	}
	if !strings.Contains(webAsset(t, "mail.js"), "PortcullisFreshAuth.start(fa") {
		t.Error("the sensitive save doesn't run the fresh sign-in")
	}
}

// TestWebMailAdminView (contract §19.13): with the admin view routed, the
// Mail tab and Settings → Mail show the warning and the read-only link for
// the provider's label, set by textContent (never in the markup); without
// it, neither; a mail provider's app is "Managed by Portcullis", never "No
// web page".
func TestWebMailAdminView(t *testing.T) {
	const warning = "Stalwart's own admin screen is read-only here. Make changes in Portcullis (Settings → Mail); changes made elsewhere would bypass Portcullis's mail safeguards."
	dom := `
const nodes = {};
function node(sel) { return nodes[sel] || (nodes[sel] = { textContent: '', children: [], appendChild(c) { this.children.push(c); } }); }
global.document = { createElement() { return { textContent: '' }; } };
global.window = {};
`
	eval := func(js string) string {
		return nodeEval(t, dom+webAsset(t, "mailprovider.js")+"\n"+webAsset(t, "mail.js")+"\n"+js)
	}
	out := eval(`const v = {wired: true, mode: "normal", admin_view: true, label: "Stalwart", warning: "w", provider: null, refused_because: []};
const skel = window.PortcullisMailProvider.tabSkeleton(v);
window.PortcullisMailProvider.fillTab({ querySelector: node }, v);
process.stdout.write(JSON.stringify({ skel, warn: node('[data-mail-admin-view-warning]').textContent, link: node('[data-mail-admin-view-open]').textContent }));`)
	var got struct{ Skel, Warn, Link string }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.Warn != warning || got.Link != "Open Stalwart's admin (read-only)" || !strings.Contains(got.Skel, "data-mail-admin-view-open") || strings.Contains(got.Skel, "Stalwart") {
		t.Errorf("Mail tab: %+v", got)
	}
	for _, v := range []string{`{wired: true, mode: "void", admin_view: false, label: "Stalwart"}`, `{wired: false, admin_view: true, label: "Stalwart"}`} {
		if h := eval(`process.stdout.write(window.PortcullisMailProvider.tabSkeleton(` + v + `))`); strings.Contains(h, "data-mail-admin-view") {
			t.Errorf("%s shows the admin view: %s", v, h)
		}
	}
	out = eval(`const st = {mail: "on", provider: {instance: "stalwart", template: "stalwart", label: "<b>S</b>", mode: "normal", admin_view: true}};
const h = window.PortcullisMail.stateHtml({mail: "on"}, st, []);
window.PortcullisMail.fillState({ querySelector: node }, st);
process.stdout.write(JSON.stringify({ skel: h, warn: node('[data-mail-admin-view-warning]').textContent, link: node('[data-mail-admin-view-open]').textContent }));`)
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.HasPrefix(got.Warn, "<b>S</b>'s own admin screen is read-only here.") || got.Link != "Open <b>S</b>'s admin (read-only)" || strings.Contains(got.Skel, "<b>S") || !strings.Contains(got.Skel, "data-mail-admin-view") {
		t.Errorf("Settings → Mail: %+v", got)
	}
	if h := eval(`process.stdout.write(window.PortcullisMail.stateHtml({mail: "on"}, {mail: "on", provider: {instance: "stalwart", template: "stalwart", label: "S", mode: "normal", admin_view: false}}, []))`); strings.Contains(h, "data-mail-admin-view") {
		t.Errorf("Settings → Mail without the view: %s", h)
	}
	src := webAsset(t, "mailprovider.js")
	for _, want := range []string{"'/api/mail/admin-view', 'POST'", "w.opener = null", `\/portcullis\/open$/`, "new MessageChannel()", "w.postMessage({ type: 'portcullis-mail-admin-hello' }, origin, [ch.port2])"} {
		if !strings.Contains(src, want) {
			t.Errorf("mailprovider.js lacks %q", want)
		}
	}
	if strings.Contains(src, "?t=") {
		t.Error("a ticket in a URL")
	}
	// A blocked tab (nit N-c): a clear message, and no ticket asked for.
	out = eval(`let calls = 0, toast = null;
window.open = () => null;
window.apiCall = async () => { calls++; return { json: async () => ({}) }; };
window.showToast = (m, k) => { toast = [m, k]; };
window.PortcullisMailProvider.openAdminView().then(() => process.stdout.write(JSON.stringify({ calls, toast })));`)
	var blocked struct {
		Calls int
		Toast []string
	}
	if err := json.Unmarshal([]byte(out), &blocked); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if blocked.Calls != 0 || len(blocked.Toast) != 2 || !strings.Contains(blocked.Toast[0], "blocked") || blocked.Toast[1] != "error" {
		t.Errorf("blocked tab: %+v", blocked)
	}
	if strings.Contains(src, "form.submit()") {
		t.Error("the Hub page posts the ticket across hosts itself (421 on a coalesced HTTP/2 connection)")
	}
	// fix-mail-admin-421: the tab is navigated with a GET to the start
	// page, the offer goes only to the view's origin, the ticket only over
	// the channel the start page answered "ready" on; no form, no URL.
	out = eval(`const sent = [], made = [];
let tab = null, toast = null;
document.createElement = (k) => { made.push(k); return { textContent: '' }; };
window.showToast = (m, k) => { toast = [m, k]; };
window.apiCall = async () => ({ json: async () => ({ url: 'https://mail-admin.example.org/portcullis/open', ticket: 'v1.abc.def' }) });
window.open = (u, n) => {
  tab = { closed: false, opener: {}, location: { href: u }, closed: false, close() { this.closed = true; },
    postMessage(msg, origin, ports) {
      sent.push({ msg, origin, href: this.location.href, ports: ports.length });
      if (sent.length < 2) return; // the first offers reach nobody (still loading)
      ports[0].onmessage = (m) => { tab.got = m.data; ports[0].close(); };
      ports[0].postMessage({ type: 'portcullis-mail-admin-ready' });
    } };
  return tab;
};
window.PortcullisMailProvider.openAdminView().then(() => setTimeout(() => {
  process.stdout.write(JSON.stringify({ sent, href: tab.location.href, opener: tab.opener, got: tab.got || null, made, toast }));
  process.exit(0);
}, 50));`)
	var hand struct {
		Sent []struct {
			Msg    struct{ Type string }
			Origin string
			Href   string
			Ports  int
		}
		Href   string
		Opener any
		Got    *struct{ Type, Ticket string }
		Made   []string
		Toast  []string
	}
	if err := json.Unmarshal([]byte(out), &hand); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if hand.Href != "https://mail-admin.example.org/portcullis/open" || hand.Opener != nil || len(hand.Sent) < 2 || hand.Got == nil ||
		hand.Got.Ticket != "v1.abc.def" || hand.Got.Type != "portcullis-mail-admin-ticket" || len(hand.Made) != 0 || hand.Toast != nil {
		t.Fatalf("hand-over: %+v", hand)
	}
	for _, m := range hand.Sent {
		if m.Origin != "https://mail-admin.example.org" || m.Msg.Type != "portcullis-mail-admin-hello" || m.Ports != 1 || strings.Contains(m.Href, "v1.") {
			t.Errorf("offer %+v", m)
		}
	}
	// Review M2 / nit3: a reply that isn't "ready" releases nothing (the
	// ticket goes only on the port that answered ready), and once it went
	// every other channel is closed.
	out = eval(`const got = [];
let n = 0, closed = 0, toast = null;
window.showToast = (m, k) => { toast = [m, k]; };
window.apiCall = async () => ({ json: async () => ({ url: 'https://mail-admin.example.org/portcullis/open', ticket: 'v1.abc.def' }) });
window.open = () => ({ closed: false, opener: {}, location: {}, close() { this.closed = true; },
  postMessage(msg, origin, ports) {
    const i = ++n, p = ports[0];
    p.on('close', () => { closed++; });
    p.onmessage = (m) => { got.push([i, m.data]); };
    if (i === 1) p.postMessage({ type: 'x' });
    if (i === 2) p.postMessage({ type: 'portcullis-mail-admin-hello' });
    if (i === 3) p.postMessage({ type: 'portcullis-mail-admin-ready' });
  } });
window.PortcullisMailProvider.openAdminView().then(() => setTimeout(() => {
  process.stdout.write(JSON.stringify({ got, offers: n, closed, toast }));
  process.exit(0);
}, 100));`)
	var only struct {
		Got    [][]any
		Offers int
		Closed int
		Toast  []string
	}
	if err := json.Unmarshal([]byte(out), &only); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(only.Got) != 1 || only.Got[0][0] != float64(3) || only.Toast != nil || only.Offers != 3 || only.Closed != 3 {
		t.Fatalf("non-ready replies / closing: %+v", only)
	}
	if m, _ := only.Got[0][1].(map[string]any); m["ticket"] != "v1.abc.def" || m["type"] != "portcullis-mail-admin-ticket" {
		t.Fatalf("the ticket message: %+v", only.Got)
	}
	// A tab closed before the start page answered: a message, no ticket.
	out = eval(`let toast = null; window.showToast = (m, k) => { toast = [m, k]; };
window.apiCall = async () => ({ json: async () => ({ url: 'https://mail-admin.example.org/portcullis/open', ticket: 'v1.abc.def' }) });
window.open = () => ({ closed: false, opener: {}, location: {}, close() { this.closed = true; }, postMessage(msg, o, ports) { this.closed = true; } });
window.PortcullisMailProvider.openAdminView().then(() => { process.stdout.write(JSON.stringify(toast)); process.exit(0); });`)
	if !strings.Contains(out, "tab was closed") {
		t.Errorf("closed tab: %s", out)
	}
	idx := webAsset(t, "index.html")
	for _, want := range []string{"'managed by Portcullis'"} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// The Marketplace card's badge (marketplace.js, rebuilt with el()).
	for _, want := range []string{"'data-managed-by-portcullis'", "text: 'Managed by Portcullis'"} {
		if !strings.Contains(webAsset(t, "marketplace.js"), want) {
			t.Errorf("marketplace.js lacks %q", want)
		}
	}
}
