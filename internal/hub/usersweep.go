package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/lldap"
)

// Stale-record sweep (fail safe). Keycloak drops its copy of a user —
// passkeys included — when a lookup finds the user gone from LDAP
// (removeInvalidUsersEnabled). The sweep lists every Keycloak user so each
// one is looked up (keycloak.RevalidateUsers). Against an empty or wrong
// LLDAP that would wipe everybody's Keycloak record, so before each run
// the Hub checks LLDAP:
//
//   - reachable (else: this run is skipped; the next one checks again),
//   - the bootstrap admin and the Hub's service account exist,
//   - the user count hasn't dropped by more than 20 % AND more than 2
//     accounts since the last successful sweep (<data>/user-sweep.json).
//
// A failed account or count check PAUSES the sweep until an admin resumes
// it (ResumeUserSweep: typed confirm, audited keycloak.sweep_resume; the
// current count becomes the new baseline). Every skip is logged loudly
// and shown as a Hub banner. Keycloak's own lookup-time removal on sign-in
// attempts is not affected by this (restore LLDAP before starting).

// LDAPUsers is the LLDAP side of the sweep check (*lldap.Client).
type LDAPUsers interface {
	ListUsers(ctx context.Context) ([]lldap.User, error)
	ServiceUser() string
}

// UserRevalidator is the Keycloak side (*keycloak.Client).
type UserRevalidator interface {
	RevalidateUsers(ctx context.Context) (int, error)
}

// SweepDropPercent / SweepDropAccounts: a drop beyond both pauses.
const (
	SweepDropPercent  = 20
	SweepDropAccounts = 2
)

// SweepResumeConfirm must be typed to resume a paused sweep.
const SweepResumeConfirm = "resume"

// UserSweepStatus is <data>/user-sweep.json and GET /api/keycloak/user-sweep.
type UserSweepStatus struct {
	// Paused: an account or count check failed; only ResumeUserSweep
	// clears it. Reason says which.
	Paused   bool      `json:"paused"`
	Reason   string    `json:"reason,omitempty"`
	PausedAt time.Time `json:"paused_at,omitempty"`
	// Skipped: the last run didn't sweep for a passing reason (LLDAP or
	// Keycloak unreachable); cleared by the next successful run.
	Skipped string `json:"skipped,omitempty"`
	// LastOKCount / LastOKAt: LLDAP's user count at the last successful
	// sweep (the drop baseline; 0 = none yet).
	LastOKCount int       `json:"last_ok_count"`
	LastOKAt    time.Time `json:"last_ok_at,omitempty"`
	LastRunAt   time.Time `json:"last_run_at,omitempty"`
	ResumedBy   string    `json:"resumed_by,omitempty"`
	ResumedAt   time.Time `json:"resumed_at,omitempty"`
	// Configured: the sweep is wired (LLDAP + Keycloak).
	Configured bool `json:"configured"`
}

type userSweep struct {
	mu   sync.Mutex // one run / resume at a time
	ll   LDAPUsers
	kc   UserRevalidator
	path string
}

// SetUserSweep wires the sweep (call before RunUserSweep).
func (h *Hub) SetUserSweep(ll LDAPUsers, kc UserRevalidator) {
	h.sweep = &userSweep{ll: ll, kc: kc, path: filepath.Join(h.cfg.DataDir, "user-sweep.json")}
}

func (s *userSweep) load() UserSweepStatus {
	var st UserSweepStatus
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			// Unreadable baseline: fail safe (pause until an admin looks).
			log.Printf("keycloak: ERROR: %s is corrupt (%v) — stale-record cleanup paused", s.path, err)
			return UserSweepStatus{Paused: true, Reason: "the sweep's state file is corrupt — resume to start a new baseline", PausedAt: time.Now().UTC()}
		}
	}
	return st
}

func (s *userSweep) save(st UserSweepStatus) {
	st.Configured = false
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := fsutil.WriteFileAtomic(s.path, append(b, '\n'), 0600); err != nil {
		log.Printf("keycloak: writing %s failed: %v", s.path, err)
	}
}

// UserSweep returns the sweep's status.
func (h *Hub) UserSweep() UserSweepStatus {
	s := h.sweep
	if s == nil {
		return UserSweepStatus{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	st.Configured = true
	return st
}

// checkLDAP runs the checks; transient = LLDAP unreachable (skip only).
func (s *userSweep) checkLDAP(ctx context.Context, baseline int) (count int, problem string, transient bool) {
	users, err := s.ll.ListUsers(ctx)
	if err != nil {
		return 0, fmt.Sprintf("LLDAP is unreachable (%v)", err), true
	}
	have := map[string]bool{}
	for _, u := range users {
		have[strings.ToLower(u.ID)] = true
	}
	var missing []string
	if !have[directory.CoreAdmin] {
		missing = append(missing, "the bootstrap admin ("+directory.CoreAdmin+")")
	}
	if svc := strings.ToLower(s.ll.ServiceUser()); svc == "" || !have[svc] {
		missing = append(missing, "the Hub's service account ("+s.ll.ServiceUser()+")")
	}
	n := len(users)
	if len(missing) > 0 {
		return n, "LLDAP has no " + strings.Join(missing, " and no "), false
	}
	if drop := baseline - n; baseline > 0 && drop > SweepDropAccounts && drop*100 > baseline*SweepDropPercent {
		return n, fmt.Sprintf("LLDAP has %d users, %d at the last cleanup (−%d, more than %d%%)", n, baseline, drop, SweepDropPercent), false
	}
	return n, "", false
}

// RunUserSweep runs one guarded sweep: true if Keycloak's users were
// revalidated.
func (h *Hub) RunUserSweep(ctx context.Context) bool {
	s := h.sweep
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	st.LastRunAt = time.Now().UTC()
	if st.Paused {
		log.Printf("keycloak: WARNING: stale-record cleanup is PAUSED (%s) — nothing is removed until an admin resumes it in the Hub", st.Reason)
		s.save(st)
		return false
	}
	n, problem, transient := s.checkLDAP(ctx, st.LastOKCount)
	if problem != "" {
		if transient {
			st.Skipped = problem
			log.Printf("keycloak: WARNING: stale-record cleanup skipped: %s", problem)
		} else {
			st.Paused, st.Reason, st.PausedAt, st.Skipped = true, problem, time.Now().UTC(), ""
			log.Printf("keycloak: ERROR: LLDAP looks wrong — stale-record cleanup PAUSED: %s. Keycloak keeps every user until an admin checks LLDAP and resumes the cleanup in the Hub", problem)
		}
		s.save(st)
		return false
	}
	if _, err := s.kc.RevalidateUsers(ctx); err != nil {
		st.Skipped = fmt.Sprintf("Keycloak: %v", err)
		log.Printf("keycloak: WARNING: stale-record cleanup failed: %v", err)
		s.save(st)
		return false
	}
	st.Skipped, st.LastOKCount, st.LastOKAt = "", n, time.Now().UTC()
	s.save(st)
	return true
}

// ResumeUserSweep resumes a paused sweep as actor (an LLDAP admin; confirm
// = SweepResumeConfirm): LLDAP's current user count becomes the new
// baseline. The account checks still apply to every run. Audited as
// keycloak.sweep_resume.
func (h *Hub) ResumeUserSweep(ctx context.Context, actor, confirm string) (st UserSweepStatus, err error) {
	s := h.sweep
	detail := ""
	defer func() { h.auditOp(actor, "keycloak.sweep_resume", "stale-record cleanup", detail, err) }()
	if s == nil {
		return st, statusErr(503, "the stale-record cleanup is not configured")
	}
	if strings.TrimSpace(actor) == "" {
		return st, statusErr(400, "no signed-in user to audit the change as")
	}
	if confirm != SweepResumeConfirm {
		return st, statusErr(400, "type %q to confirm", SweepResumeConfirm)
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI == nil {
		return st, statusErr(503, "users & groups is not available")
	}
	if err := groupsAPI.ResolveActor(ctx, actor); err != nil {
		return st, &StatusError{Status: 403, Err: fmt.Errorf("%s can't resume the cleanup: %w", actor, err)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.load()
	if !st.Paused {
		return st, statusErr(409, "the stale-record cleanup isn't paused")
	}
	users, lerr := s.ll.ListUsers(ctx)
	if lerr != nil {
		return st, &StatusError{Status: 503, Err: fmt.Errorf("LLDAP is unreachable: %w", lerr)}
	}
	detail = fmt.Sprintf("was paused: %s; new baseline %d users", st.Reason, len(users))
	st = UserSweepStatus{LastOKCount: len(users), LastOKAt: st.LastOKAt, ResumedBy: actor, ResumedAt: time.Now().UTC()}
	s.save(st)
	log.Printf("keycloak: stale-record cleanup resumed by %s (baseline %d LLDAP users)", actor, len(users))
	st.Configured = true
	return st, nil
}
