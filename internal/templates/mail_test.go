package templates

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMailVectors: every shared vector's first refusal is want_error
// ("" = the template loads), built as template mailsrv.
func TestMailVectors(t *testing.T) {
	vs := readMailVectors(t)
	if len(vs) < 35 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		_, err := build(mailVectorID, "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != v.WantError {
			t.Errorf("%s:\n got %q\nwant %q", v.Name, got, v.WantError)
		}
	}
}

func mailVectorByName(t *testing.T, name string) mailVector {
	t.Helper()
	for _, v := range readMailVectors(t) {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no vector %q", name)
	return mailVector{}
}

// TestMailBlockDecodes: the stalwart-shaped block decodes into Mail.
func TestMailBlockDecodes(t *testing.T) {
	v := mailVectorByName(t, "stalwart-shaped ok")
	tp, err := build(mailVectorID, "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	b := tp.Manifest.Mail
	if b == nil || b.Label != "Stalwart" || b.APIVersion != 1 || b.API != (Endpoint{"adapter", 8080}) ||
		b.Listeners != (Listeners{"stalwart", 10025, 10465, 10587, 10993}) || b.Wellknown.Port != 8081 || b.Metrics.Port != 9100 ||
		b.ServerMetrics == nil || b.ServerMetrics.Path != "/metrics/prometheus" || len(b.TLS) != 2 || len(b.Gated) != 2 ||
		b.Sessions.Restart != "stalwart" || b.Export == nil || b.Export.Argv[3] != MailFormerIDArg {
		t.Fatalf("%+v", b)
	}
	f := mailVectorByName(t, "mail-fake-shaped ok")
	tf, err := build(mailVectorID, "src", "", []byte(f.Manifest), []byte(f.Compose), "example.org", nil)
	if err != nil || tf.Manifest.Mail.ServerMetrics != nil || tf.Manifest.Mail.Export != nil {
		t.Fatalf("%+v %v", tf.Manifest.Mail, err)
	}
}

// writeMailTemplate writes a template directory dir/<id> from the
// stalwart-shaped vector with its two bound files.
func writeMailTemplate(t *testing.T, dir, id string) string {
	t.Helper()
	v := mailVectorByName(t, "stalwart-shaped ok")
	p := filepath.Join(dir, id)
	for name, b := range map[string]string{
		"manifest.yaml": v.Manifest, "compose.yml": strings.ReplaceAll(v.Compose, "templates/mailsrv/", "templates/"+id+"/"),
		"gate.sh": "#!/bin/sh\nexit 1\n", "unbound.conf": "server:\n", "sub/notes.txt": "x",
	} {
		f := filepath.Join(p, name)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func mailHashOf(t *testing.T, p string) string {
	t.Helper()
	tp, err := Load(filepath.Dir(p), filepath.Base(p), "src", "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := MailBlockHash(p, tp.Manifest.Mail, tp.ReadCompose())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestMailBlockHashCoversTree (P4): a byte change in any file under the
// template directory, the compose file or the block changes the hash; an
// unrelated template's change doesn't; it is stable otherwise.
func TestMailBlockHashCoversTree(t *testing.T) {
	dir := t.TempDir()
	p := writeMailTemplate(t, dir, "mailsrv")
	other := writeMailTemplate(t, dir, "othermail")
	h0 := mailHashOf(t, p)
	if len(h0) != 64 || mailHashOf(t, p) != h0 {
		t.Fatalf("unstable or malformed: %q", h0)
	}
	if err := os.WriteFile(filepath.Join(other, "gate.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mailHashOf(t, p) != h0 {
		t.Fatal("an unrelated template changed the hash")
	}
	for _, edit := range []struct{ file, from, to string }{
		{"sub/notes.txt", "x", "y"},
		{"gate.sh", "exit 1", "exit 2"},
		{"compose.yml", "image: x\n    cap_drop: [ALL]\n    volumes:\n      - ./templates/mailsrv/unbound.conf", "image: y\n    cap_drop: [ALL]\n    volumes:\n      - ./templates/mailsrv/unbound.conf"},
		{"manifest.yaml", "label: Stalwart", "label: Stalwart 2"},
	} {
		f := filepath.Join(p, edit.file)
		b, _ := os.ReadFile(f)
		nb := strings.Replace(string(b), edit.from, edit.to, 1)
		if nb == string(b) {
			t.Fatalf("%s: edit missed", edit.file)
		}
		if err := os.WriteFile(f, []byte(nb), 0o644); err != nil {
			t.Fatal(err)
		}
		h := mailHashOf(t, p)
		if h == h0 {
			t.Errorf("%s: the hash didn't change", edit.file)
		}
		h0 = h
	}
	// A new file and a symlink count too.
	if err := os.WriteFile(filepath.Join(p, "new.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h1 := mailHashOf(t, p)
	if h1 == h0 {
		t.Error("a new empty file didn't change the hash")
	}
	if err := os.Symlink("gate.sh", filepath.Join(p, "link")); err != nil {
		t.Fatal(err)
	}
	if mailHashOf(t, p) == h1 {
		t.Error("a symlink didn't change the hash")
	}
	if _, err := MailBlockHash(p, nil, nil); err == nil {
		t.Error("no block hashed")
	}
}

// TestMailBindSymlinkRefused: a bound template file that resolves
// outside the template directory is refused when the template loads.
func TestMailBindSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	p := writeMailTemplate(t, dir, "mailsrv")
	if err := os.Remove(filepath.Join(p, "gate.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(p, "gate.sh")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, "mailsrv", "src", "example.org", nil)
	want := "mail: bootstrap mounts ./templates/mailsrv/gate.sh:/gate.sh:ro: it resolves outside templates/mailsrv/ (a symlink)"
	if err == nil || err.Error() != want {
		t.Fatalf("%v\nwant %s", err, want)
	}
}

// TestTemplateWithBadMailSkipped: Discover logs and skips a template
// whose mail: block fails, keeping the others.
func TestTemplateWithBadMailSkipped(t *testing.T) {
	dir := t.TempDir()
	writeMailTemplate(t, dir, "goodmail")
	bad := writeMailTemplate(t, dir, "badmail")
	f := filepath.Join(bad, "manifest.yaml")
	b, _ := os.ReadFile(f)
	if err := os.WriteFile(f, bytes.Replace(b, []byte("api_version: 1"), []byte("api_version: 2"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	ts := Discover(dir, "src", "example.org", nil)
	if len(ts) != 1 || ts[0].ID != "goodmail" || !ts[0].MailProvider {
		t.Fatalf("%d templates", len(ts))
	}
	if !strings.Contains(logs.String(), "Skipping template badmail: mail.api_version: only 1") {
		t.Fatalf("log %q", logs.String())
	}
}

// TestMarketplaceMailBadge: the catalog entry says mail_provider for a
// template with a valid mail: block (and its instances keep it); false
// otherwise.
func TestMarketplaceMailBadge(t *testing.T) {
	v := mailVectorByName(t, "stalwart-shaped ok")
	tp, err := build(mailVectorID, "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := tp.Instance(tp.ID, nil, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []Template{tp, inst} {
		b, _ := json.Marshal(x)
		if !strings.Contains(string(b), `"mail_provider":true`) {
			t.Fatalf("no badge: %s", b)
		}
	}
	n := mailVectorByName(t, "no mail block ok")
	tn, err := build(mailVectorID, "src", "", []byte(n.Manifest), []byte(n.Compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(tn); !strings.Contains(string(b), `"mail_provider":false`) {
		t.Fatalf("badge on a non-mail template: %s", b)
	}
}

// TestCoreNamesIncludeMailSlot (P9): the slot's core names are reserved;
// the removed mail core names stay reserved until core has merged.
func TestCoreNamesIncludeMailSlot(t *testing.T) {
	if !coreVolumes["mail_slot"] {
		t.Error("volume mail_slot not reserved")
	}
	for _, a := range []string{"mail-api", "mail-provider-metrics", "mail-provider-server-metrics", "Mail-API."} {
		if !reservedDNSName(a) {
			t.Errorf("alias %s not reserved", a)
		}
	}
	for _, s := range []string{"mail", "mailctl", "mail-resolver", "mail-cert"} {
		if !coreServices[s] {
			t.Errorf("service %s no longer reserved", s)
		}
	}
	for _, n := range []string{"portcullis-mail-api", "portcullis-metrics-mail"} {
		c := "services:\n  a:\n    image: x\n    networks: [" + n + "]\nnetworks:\n  " + n + ":\n    external: true\n"
		if err := checkCoreRefs([]byte(c), nil); err == nil {
			t.Errorf("network %s joinable", n)
		}
	}
	c := "services:\n  a:\n    image: x\n    volumes: [\"slot:/s\"]\nvolumes:\n  slot:\n    external: true\n    name: portcullis_mail_slot\n"
	if err := checkCoreRefs([]byte(c), nil); err == nil {
		t.Error("portcullis_mail_slot mountable")
	}
}

// TestMailFieldEdges: shapes the vectors don't spell out.
func TestMailFieldEdges(t *testing.T) {
	v := mailVectorByName(t, "stalwart-shaped ok")
	for _, c := range []struct{ from, to, want string }{
		{"smtp: 10025", "smtp: 25", "mail.listeners: port must be 1024–65535"},
		{"smtp: 10025", `smtp: "10025"`, "mail.listeners: port must be 1024–65535"},
		{"smtp: 10025", "smtp: [10025]", "mail.listeners: exactly smtp, submissions, submission and imaps, on one service"},
		{", imaps: 10993}", "}", "mail.listeners: exactly smtp, submissions, submission and imaps, on one service"},
		{"port: 8080}", `port: "8080"}`, "mail.api: port must be 1024–65535"},
		{"port: 8080}", "port: 65536}", "mail.api: port must be 1024–65535"},
		{"tls: [stalwart, adapter]", "tls: stalwart", "mail.tls: service stalwart is not a service of this template"},
		{"tls: [stalwart, adapter]", "tls: [stalwart, adapter, nope]", "mail.tls: service nope is not a service of this template"},
		{"sessions: {restart: stalwart}", "sessions: {restart: bootstrap}", "mail.sessions.restart: bootstrap is a job"},
		{"sessions: {restart: stalwart}", "sessions: {restart: nope}", "mail.sessions.restart: service nope is not a service of this template"},
		{`"{former_id}"]`, `"{former_id}", "{former_id}"]`, "mail.export.argv: exactly one {former_id}"},
		{`"{former_id}"]`, `"--id={former_id}"]`, "mail.export.argv: exactly one {former_id}"},
		{"path: /metrics/prometheus", "path: /a/../b", "mail.server_metrics.path: an absolute URL path"},
		{"label: Stalwart", "label: \"two\\nlines\"", "mail.label: 1–64 characters, one line"},
		{"api_version: 1", "api_version: \"1\"", "mail.api_version: only 1"},
		{"  label: Stalwart\n", "", "mail.label: required"},
		{"  wellknown: {service: adapter, port: 8081}\n", "", "mail.wellknown: required"},
		{"  label: Stalwart\n", "  label: Stalwart\n  extra: 1\n", "mail: unknown key extra"},
	} {
		m := strings.Replace(v.Manifest, c.from, c.to, 1)
		if m == v.Manifest {
			t.Fatalf("edit %q missed", c.from)
		}
		_, err := build(mailVectorID, "src", "", []byte(m), []byte(v.Compose), "example.org", nil)
		if err == nil || err.Error() != c.want {
			t.Errorf("%q → %q: %v, want %q", c.from, c.to, err, c.want)
		}
	}
	for _, c := range []struct{ from, to, want string }{
		{"  egress: {}\n", "  egress: {enable_ipv6: false}\n", ""},
		{"  egress: {}\n", "  egress: {enable_ipv6: \"${V6:-false}\"}\n", "mail: network egress enables IPv6"},
		{"    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE]\n", "    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE]\n    pid: host\n", "mail: stalwart sets pid: a mail provider keeps its own pid and ipc namespaces"},
		{"      - adapter-data:/data\n    networks: [internal]\n  resolver", "      - adapter-data:/data\n      - /var/run/docker.sock:/var/run/docker.sock\n    networks: [internal]\n  resolver",
			"mail: adapter mounts /var/run/docker.sock:/var/run/docker.sock: a mail template's binds start with ./ and have no .. segment"},
	} {
		cp := strings.Replace(v.Compose, c.from, c.to, 1)
		if cp == v.Compose {
			t.Fatalf("edit %q missed", c.from)
		}
		_, err := build(mailVectorID, "src", "", []byte(v.Manifest), []byte(cp), "example.org", nil)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%q: %q, want %q", c.to, got, c.want)
		}
	}
}
