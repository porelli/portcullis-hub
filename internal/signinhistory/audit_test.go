package signinhistory

import (
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

func TestHistorySSHCertificate(t *testing.T) {
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		e    directory.AuditEntry
		ok   bool
		kind Kind
	}{
		{directory.AuditEntry{Time: at, Actor: "alice", Action: "ssh.certificate.issue", Target: "alice", Detail: "web: u:alice@web until 17:00", Result: "ok"}, true, KindSSHCertificate},
		{directory.AuditEntry{Time: at, Actor: "alice", Action: "ssh.certificate.revoke", Target: "alice", Result: "ok"}, true, KindSSHCertificate},
		{directory.AuditEntry{Time: at, Actor: "-", Action: "ssh.certificate.revoke", Target: "alice", Detail: "left ssh_web", Result: "ok"}, true, KindSSHCertificate},
		{directory.AuditEntry{Time: at, Actor: "root", Action: "ssh.certificate.revoke", Target: "alice", Result: "ok"}, true, KindHelp},
		{directory.AuditEntry{Time: at, Actor: "alice", Action: "ssh.certificate.issue", Target: "alice", Result: "refused"}, false, ""},
		{directory.AuditEntry{Time: at, Actor: "alice", Action: "ssh.grant.create", Target: "g", Result: "ok"}, false, ""},
	} {
		got, ok := FromAudit(tc.e, "alice")
		if ok != tc.ok || (ok && got.Kind != tc.kind) {
			t.Errorf("%s by %s (%s): %v %v", tc.e.Action, tc.e.Actor, tc.e.Result, got.Kind, ok)
		}
	}
	if string(KindSSHCertificate) != "ssh_certificate" {
		t.Error("kind name")
	}
}
