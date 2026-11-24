package templates

import (
	"strings"
	"testing"
)

// mail_sender (contract §3 Manifest reference, §19.14): a label of 1–64
// characters on one line, no other key.
func TestSenderLabelValidation(t *testing.T) {
	ok, err := buildDir(t, catHead+"mail_sender:\n  label: Firefox accounts\n", nil)
	if err != nil {
		t.Fatalf("a good mail_sender: %v", err)
	}
	if ok.Manifest.MailSender == nil || ok.Manifest.MailSender.Label != "Firefox accounts" {
		t.Fatalf("MailSender = %+v", ok.Manifest.MailSender)
	}
	if none, err := buildDir(t, catHead, nil); err != nil || none.Manifest.MailSender != nil {
		t.Fatalf("no mail_sender: %+v, %v", none.Manifest.MailSender, err)
	}
	if max, err := buildDir(t, catHead+"mail_sender:\n  label: "+strings.Repeat("é", MailSenderLabelMax)+"\n", nil); err != nil || max.Manifest.MailSender == nil {
		t.Fatalf("a 64-rune label: %v", err)
	}
	for name, body := range map[string]string{
		"empty":       "mail_sender:\n  label: \"\"\n",
		"missing":     "mail_sender: {}\n",
		"too long":    "mail_sender:\n  label: " + strings.Repeat("é", MailSenderLabelMax+1) + "\n",
		"newline":     "mail_sender:\n  label: \"two\\nlines\"\n",
		"tab":         "mail_sender:\n  label: \"a\\tb\"\n",
		"unknown key": "mail_sender:\n  label: X\n  from: x@example.org\n",
		"not a map":   "mail_sender: yes\n",
		"null":        "mail_sender: null\n",
	} {
		if _, err := buildDir(t, catHead+body, nil); err == nil || !strings.Contains(err.Error(), "mail_sender") {
			t.Errorf("%s: err = %v, want a mail_sender refusal", name, err)
		}
	}
}

// The five variables are the Hub's: a manifest may not declare them.
func TestSenderVarsReserved(t *testing.T) {
	for _, k := range MailSenderVars {
		if !ReservedVar(k) {
			t.Errorf("%s isn't reserved", k)
		}
	}
	if len(MailSenderVars) != 5 {
		t.Fatalf("MailSenderVars = %v", MailSenderVars)
	}
}
