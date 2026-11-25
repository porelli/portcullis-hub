package templates

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// MailSender is the manifest's optional mail_sender: block (contract §3
// Manifest reference, §19.14): the app sends outbound mail, so the Hub
// asks the wired mail provider for a submission-only sender account and
// delivers the five PORTCULLIS_MAIL_SENDER_* variables.
type MailSender struct {
	// Label is the sender's display name (the From: header's name): 1–64
	// characters on one line.
	Label string `yaml:"label" json:"label"`
}

// MailSenderLabelMax is the longest mail_sender.label (runes).
const MailSenderLabelMax = 64

// The five variables the Hub writes into a sender instance's .env
// (§19.14): all empty while no provider is wired or mail is off.
const (
	VarMailSenderPrefix   = "PORTCULLIS_MAIL_SENDER_"
	VarMailSenderHost     = VarMailSenderPrefix + "HOST"
	VarMailSenderPort     = VarMailSenderPrefix + "PORT"
	VarMailSenderUser     = VarMailSenderPrefix + "USER"
	VarMailSenderPassword = VarMailSenderPrefix + "PASSWORD"
	VarMailSenderFrom     = VarMailSenderPrefix + "FROM"
)

// MailSenderVars are the five, in the contract's order.
var MailSenderVars = []string{VarMailSenderHost, VarMailSenderPort, VarMailSenderUser, VarMailSenderPassword, VarMailSenderFrom}

// MailSenderLabelProblem is why label can't be a sender label ("" = it
// can): one line of 1–64 characters without ' or \ (FROM is
// single-quoted in the .env, and an RFC 5322 name-addr escapes \).
func MailSenderLabelProblem(label string) string {
	n := utf8.RuneCountInString(label)
	if n < 1 || n > MailSenderLabelMax || HasHiddenText(label) || strings.ContainsAny(label, "\r\n\t'\\") {
		return fmt.Sprintf("mail_sender.label must be one line of 1–%d characters without ' or \\", MailSenderLabelMax)
	}
	return ""
}

// validateMailSenderNode judges the mail_sender block as written: a
// mapping with exactly the key label (null or any other shape refused).
func validateMailSenderNode(root *yaml.Node) error {
	if root == nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "mail_sender" {
			continue
		}
		v := doc.Content[i+1]
		if v.Kind != yaml.MappingNode {
			return fmt.Errorf("mail_sender must be a mapping with label")
		}
		seen := false
		for j := 0; j+1 < len(v.Content); j += 2 {
			if k := v.Content[j].Value; k != "label" {
				return fmt.Errorf("mail_sender: unknown key %q (only label)", clipKey(k))
			}
			seen = true
		}
		if !seen {
			return fmt.Errorf("mail_sender.label is required")
		}
	}
	return nil
}

// clipKey bounds a key quoted in an error.
func clipKey(k string) string {
	if len(k) > 40 {
		return k[:40]
	}
	return k
}

// validateMailSender checks the decoded block (ValidateManifest).
func validateMailSender(m *Manifest) error {
	if m.MailSender == nil {
		return nil
	}
	if p := MailSenderLabelProblem(m.MailSender.Label); p != "" {
		return fmt.Errorf("%s", p)
	}
	return nil
}
