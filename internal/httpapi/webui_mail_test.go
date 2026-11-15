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
