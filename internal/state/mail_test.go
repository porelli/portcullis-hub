package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMailDefaultsAndRoundTrip: a new state and a file without mail get
// the defaults; settings and credential rows survive a save; a
// hand-edited out-of-range value refuses the load.
func TestMailDefaultsAndRoundTrip(t *testing.T) {
	if s := New(); s.Mail.Spam.RejectScore != 15 || s.Mail.Spam.JunkScore != 5 || !s.Mail.Spam.Spamhaus || s.Mail.Limits.RecipientsPerDay != 1000 {
		t.Fatalf("defaults %+v", s.Mail)
	}
	p := filepath.Join(t.TempDir(), "state.yaml")
	os.WriteFile(p, []byte("enabled: []\n"), 0600)
	s, err := Load(p)
	if err != nil || s.Mail.Limits.RecipientsPerHour != 300 || s.MailCredentials == nil {
		t.Fatalf("Load without mail = %+v, %v", s, err)
	}
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	s.Mail.Domains = map[string]MailDomain{"team-b.test": {Enabled: true, Groups: []string{"team_b"}}}
	s.Mail.Generation = 7
	s.MailCredentials["alice"] = []MailCredential{{ID: "m1", StalwartID: "3", Label: "iPhone", UUID: "u", CreatedAt: now, CreatedBy: "alice"}}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	b, _ := Load(p)
	if b.Mail.Generation != 7 || !b.Mail.Domains["team-b.test"].Enabled || len(b.MailCredentials["alice"]) != 1 || !b.MailCredentials["alice"][0].Active() {
		t.Fatalf("round trip %+v %+v", b.Mail, b.MailCredentials)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "mail_credentials:") || !strings.Contains(string(raw), "stalwart_id: \"3\"") {
		t.Fatalf("state.yaml:\n%s", raw)
	}
	for _, bad := range []string{
		"mail:\n  spam: {reject_score: 5, junk_score: 5}\n",
		"mail:\n  limits: {recipients_per_hour: 0, recipients_per_day: 10}\n",
		"mail:\n  quotas: [{group: g, bytes: 0}]\n",
		"mail:\n  generation: -1\n",
	} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "mail:") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
