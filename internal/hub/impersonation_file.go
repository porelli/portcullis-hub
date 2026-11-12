package hub

// The published impersonation file hub_data/impersonation.json (contract
// §8.1 "Impersonation", D37): the Keycloak extension and group-gate read
// it and fail closed, Keycloak strictly (an unknown field or a value
// outside its rule makes the whole file invalid). So the Hub writes only
// what those rules accept: a record that would break them is left out
// (logged), which makes it not live — never a broken file.

import (
	"encoding/json"
	"log"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// ImpersonationFileName is the published file in the Hub's data
// directory (core mounts it as /hub-data/impersonation.json).
const ImpersonationFileName = "impersonation.json"

// ImpersonationFileVersion is the file's version.
const ImpersonationFileVersion = 1

// The file's windows (D37): a pending record is listed while created is
// under 120 s old, an ended one stays in sessions for an hour, and the
// file is rewritten every minute (group-gate treats one older than 300 s
// as unreadable).
const (
	impPendingFor   = 120 * time.Second
	impSessionsKeep = time.Hour
	impRewriteEvery = time.Minute
)

// impFile is impersonation.json (D37).
type impFile struct {
	Version  int                    `json:"version"`
	Allowed  bool                   `json:"allowed"`
	Written  string                 `json:"written"`
	Clients  []string               `json:"clients"`
	Pending  []impPending           `json:"pending"`
	Sessions []impSession           `json:"sessions"`
	Notices  map[string][]impNotice `json:"notices"`
}

type impPending struct {
	ID       string `json:"id"`
	Admin    string `json:"admin"`
	AdminSID string `json:"admin_sid"`
	Target   string `json:"target"`
	Reason   string `json:"reason"`
	Fresh    string `json:"fresh"`
	FreshAt  string `json:"fresh_at"`
	Created  string `json:"created"`
	Until    string `json:"until"`
}

type impSession struct {
	ID      string  `json:"id"`
	Admin   string  `json:"admin"`
	Target  string  `json:"target"`
	Reason  string  `json:"reason"`
	Started string  `json:"started"`
	Until   string  `json:"until"`
	Ended   *string `json:"ended"`
}

type impNotice struct {
	ID      string   `json:"id"`
	Admin   string   `json:"admin"`
	Started string   `json:"started"`
	Ended   string   `json:"ended"`
	Reason  string   `json:"reason"`
	Apps    []impApp `json:"apps"`
}

type impApp struct {
	Name       string `json:"name"`
	OwnSession bool   `json:"own_session"`
}

// The readers' rules (contract §8.1; the Keycloak extension's
// ImpersonationFile).
var (
	impUsernameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	impIDRe        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	impSessionIDRe = regexp.MustCompile(`^[A-Za-z0-9._:~-]{1,128}$`)
)

// impTouchMethods are the fresh touches an impersonation starts with
// (D36.9): a security key or a YubiKey certificate.
var impTouchMethods = []signin.Method{signin.SecurityKey, signin.YubiKeyCert}

// controlOrBidi is the readers' forbidden set: a control character (C0,
// DEL, C1), the line and paragraph separators, or a bidi control.
func controlOrBidi(r rune) bool {
	return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 || r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// validImpReason is the reason rule (D36.4, the readers'): 3–200 runes,
// valid UTF-8, no control or bidi character (so one line).
func validImpReason(s string) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= 3 && n <= 200 && strings.IndexFunc(s, controlOrBidi) < 0
}

// impAppName is an app's name as the file may carry it (1–200 runes, no
// control or bidi character): forbidden characters dropped, clipped; ""
// when nothing is left.
func impAppName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || controlOrBidi(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:200])
	}
	return s
}

// impTime is t as the file writes it: RFC 3339, UTC, whole seconds.
func impTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// validImpRecord: r's fields are inside the readers' rules (the fields
// every list carries).
func validImpRecord(r state.Impersonation) bool {
	return impIDRe.MatchString(r.ID) && impUsernameRe.MatchString(r.Admin) && impUsernameRe.MatchString(r.Target) &&
		validImpReason(r.Reason) && !r.Started.IsZero() && !r.Until.IsZero()
}

// validImpPending: r may be a pending record (admin_sid a session id,
// fresh a touch method, fresh_at at most created + 5 s).
func validImpPending(r state.Impersonation) bool {
	return impSessionIDRe.MatchString(r.AdminSID) && slices.Contains(impTouchMethods, signin.Method(r.Fresh)) &&
		!r.FreshAt.IsZero() && !r.FreshAt.Truncate(time.Second).After(r.Started.Truncate(time.Second).Add(5*time.Second))
}

// impFileClient: id may be in clients (never the fresh-auth client or an
// AI client: signInClientIDs already skips ai_client, F30; this is the
// belt to those braces) and is inside the reader's rule.
func impFileClient(id string) bool {
	if id == "" || len(id) > 255 || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return false
	}
	switch id {
	case freshauth.ClientID, keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode, keycloak.AIClientIDs.Generic:
		return false
	}
	return !strings.HasPrefix(strings.ToLower(id), keycloak.AIClientPrefix)
}

// historyDaysLocked is history_days as the records and notices keep it
// (outside its bounds: the default). Caller holds mu.
func (h *Hub) historyDaysLocked() int {
	d := h.st.SignIn.Limits.HistoryDays
	if d < state.MinHistoryDays || d > state.MaxHistoryDays {
		return state.DefaultHistoryDays
	}
	return d
}

// impersonationFileLocked builds the file from state at now. Caller
// holds mu (either lock).
func (h *Hub) impersonationFileLocked(now time.Time) impFile {
	doc := impFile{
		Version: ImpersonationFileVersion, Allowed: !h.st.SignIn.ImpersonationOff, Written: impTime(now),
		Clients: []string{keycloak.ForwardAuthClient}, Pending: []impPending{}, Sessions: []impSession{},
		Notices: map[string][]impNotice{},
	}
	for _, c := range slices.Sorted(maps.Keys(h.keycloakSignInLocked().Clients)) {
		if c != keycloak.ForwardAuthClient && impFileClient(c) {
			doc.Clients = append(doc.Clients, c)
		}
	}
	keepNotices := now.AddDate(0, 0, -h.historyDaysLocked())
	seen := map[string]bool{}
	for _, r := range h.st.Impersonations {
		if !validImpRecord(r) || seen[r.ID] {
			log.Printf("impersonation: a record (id %q) breaks the file's rules or repeats an id: left out of %s (not live)", clip(r.ID, 40), ImpersonationFileName)
			continue
		}
		seen[r.ID] = true
		running := r.Running()
		if running && now.Sub(r.Started) < impPendingFor {
			if validImpPending(r) {
				doc.Pending = append(doc.Pending, impPending{ID: r.ID, Admin: r.Admin, AdminSID: r.AdminSID, Target: r.Target,
					Reason: r.Reason, Fresh: r.Fresh, FreshAt: impTime(r.FreshAt), Created: impTime(r.Started), Until: impTime(r.Until)})
			} else {
				log.Printf("impersonation: %s: its pending fields break the file's rules: not pending", r.ID)
			}
		}
		if running || now.Sub(r.Ended) < impSessionsKeep {
			s := impSession{ID: r.ID, Admin: r.Admin, Target: r.Target, Reason: r.Reason, Started: impTime(r.Started), Until: impTime(r.Until)}
			if !running {
				e := impTime(r.Ended)
				s.Ended = &e
			}
			doc.Sessions = append(doc.Sessions, s)
		}
		if !running && r.Used && r.Ended.After(keepNotices) {
			n := impNotice{ID: r.ID, Admin: r.Admin, Started: impTime(r.Started), Ended: impTime(r.Ended), Reason: r.Reason, Apps: []impApp{}}
			for _, a := range r.Apps {
				if name := impAppName(a.Name); name != "" {
					n.Apps = append(n.Apps, impApp{Name: name, OwnSession: a.OwnSession})
				}
			}
			doc.Notices[r.Target] = append(doc.Notices[r.Target], n)
		}
	}
	return doc
}

func (h *Hub) impersonationFilePath() string {
	return filepath.Join(h.cfg.DataDir, ImpersonationFileName)
}

// writeImpersonationFileLocked writes the file atomically, mode 0644
// (Keycloak and group-gate read it from a read-only mount as other
// users). Caller holds mu (either lock: the file is built and renamed
// under it, so an older snapshot never replaces a newer one). A failed
// write is retried by RunImpersonationExpiry's next tick.
func (h *Hub) writeImpersonationFileLocked() error {
	h.imp.fileMu.Lock()
	defer h.imp.fileMu.Unlock()
	now := h.impNow()
	b, err := json.MarshalIndent(h.impersonationFileLocked(now), "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(h.impersonationFilePath(), append(b, '\n'), 0644)
	}
	if err != nil {
		h.imp.fileFailed = true
		log.Printf("impersonation: writing %s: %v (readers fail closed: nobody can start or stay signed in as someone else until it is written)", ImpersonationFileName, err)
		return err
	}
	h.imp.fileFailed, h.imp.written = false, now
	return nil
}

// impFileFailed: the last write failed. Takes the file lock.
func (h *Hub) impFileFailed() bool {
	h.imp.fileMu.Lock()
	defer h.imp.fileMu.Unlock()
	return h.imp.fileFailed
}

// impersonationFileDue: the file failed, is a minute old or was written
// "later" than now (the clock went back). Takes the file lock.
func (h *Hub) impersonationFileDue(now time.Time) bool {
	h.imp.fileMu.Lock()
	defer h.imp.fileMu.Unlock()
	// A written ahead of now (the clock set back) is due too: never wait
	// for the clock to catch up.
	return h.imp.fileFailed || now.Sub(h.imp.written) >= impRewriteEvery || now.Before(h.imp.written)
}
