package signinhistory

import (
	"context"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// historyAction: the audit actions the history keeps (§8.2), and the
// detail's text for each ("" for cert.*: its action names it).
func historyAction(action string) (string, bool) {
	switch action {
	case "signin.password":
		return "password changed", true
	case "user.password":
		return "password set", true
	case "user.invite":
		return "setup link sent", true
	case "user.remove_passkeys":
		return "passkeys removed", true
	}
	switch {
	case action == "cert.create":
		return "certificate created", true
	case action == "cert.revoke":
		return "certificate revoked", true
	case action == "cert.renew":
		return "certificate renewed", true
	case strings.HasPrefix(action, "cert."):
		return "certificate " + strings.TrimPrefix(action, "cert."), true
	}
	return "", false
}

// FromAudit maps one of user's audit entries (§8.2, D28): only the
// actions cert.*, signin.password, user.password, user.invite and
// user.remove_passkeys, and only those that happened (result ok). An
// entry whose actor isn't user is help (By the actor); one by user is
// certificate for cert.*, and dropped for anything else. Detail is what
// was done, then the audit entry's detail (which never holds a secret).
func FromAudit(e directory.AuditEntry, user string) (Entry, bool) {
	what, ok := historyAction(e.Action)
	if !ok || (e.Result != "" && e.Result != "ok") {
		return Entry{}, false
	}
	out := Entry{Time: e.Time.UTC()}
	switch {
	case !strings.EqualFold(strings.TrimSpace(e.Actor), strings.TrimSpace(user)):
		out.Kind, out.By = KindHelp, Clean(e.Actor, maxBy)
	case strings.HasPrefix(e.Action, "cert."):
		out.Kind = KindCertificate
	default:
		return Entry{}, false
	}
	detail := what
	if d := strings.TrimSpace(e.Detail); d != "" {
		detail += ": " + d
	}
	out.Detail = Clean(detail, maxDetail)
	return withScore(out), true
}

// AuditReader reads the audit newest first (directory.Service's
// RecentMatching).
type AuditReader func(n int, maxScan int64, keep func(directory.AuditEntry) bool) ([]directory.AuditEntry, error)

// AuditSource is the audit source: ForUser(user)'s entries that FromAudit
// keeps, in [since, before), reading at most the audit's last
// directory.AuditScan bytes.
type AuditSource struct{ Read AuditReader }

// Entries implements Source.
func (s AuditSource) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	about := directory.ForUser(user)
	keep := func(e directory.AuditEntry) bool {
		if e.Time.Before(since) || !e.Time.Before(before) || !about(e) {
			return false
		}
		_, ok := FromAudit(e, user)
		return ok
	}
	if limit < 1 {
		return []Entry{}, nil
	}
	got, err := s.Read(limit, directory.AuditScan, keep)
	if err != nil {
		return nil, err
	}
	out := []Entry{}
	for _, e := range got {
		if en, ok := FromAudit(e, user); ok {
			out = append(out, en)
		}
	}
	return out, nil
}
