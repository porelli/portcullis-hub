package directory

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/lldap"
)

// Verified emails (contract §9.8). directory.yaml email_verified.<LLDAP
// uuid> = {email, at, by}: the email counts as verified only while it is
// still the person's LLDAP email (compared trimmed and lowercased), so
// any change of the email — through the Hub or LLDAP's own UI — makes it
// unverified, and a re-created username (a new uuid) starts unverified.

// EmailVerification is one person's verified email.
type EmailVerification struct {
	Email string    `yaml:"email"`
	At    time.Time `yaml:"at"`
	By    string    `yaml:"by"` // "code" | "admin:<username>"
}

// ByCode is EmailVerification.By for an email proved with a code.
const ByCode = "code"

// ErrCodeExpiredMsg is the contract's 410 text (§9.8): the code expired,
// was used up, or the email changed since it was sent.
const ErrCodeExpiredMsg = "this code has expired: ask for a new one"

// normEmail is an email as §9.8 compares it.
func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// verifiedEmail answers current (trimmed) and true when cfg records it
// as uuid's verified email.
func verifiedEmail(cfg *Config, uuid, current string) (string, bool) {
	if cfg == nil || uuid == "" || normEmail(current) == "" {
		return "", false
	}
	v, ok := cfg.EmailVerified[uuid]
	if !ok || normEmail(v.Email) != normEmail(current) {
		return "", false
	}
	return strings.TrimSpace(current), true
}

// mayVerify: c's change of target's email stores it verified (contract
// §9.8 case 2): someone else, never through the AI (an email the AI sets
// stays unverified), and an admin or a delegate who still holds
// edit_details on target in this snapshot — re-checked here, at the
// moment of recording, never taken from the Caller resolved before the
// lock. sn and cfg are the run's reads (cfg nil: no delegate verifies).
// Caller holds s.mu.
func (s *Service) mayVerify(c *Caller, target string, sn *snapshot, cfg *Config) bool {
	if c == nil || c.Via == ViaAI || strings.EqualFold(strings.TrimSpace(c.User), strings.TrimSpace(target)) {
		return false
	}
	if c.Admin {
		return memberOf(sn.groups[lldap.AdminGroup], c.User)
	}
	if cfg == nil || !c.Perms[PermEditDetails] {
		return false
	}
	g, ok := sn.groups[cfg.Permissions[PermEditDetails]]
	if !ok || !memberOf(g, c.User) {
		return false
	}
	return s.authorize(c, PermEditDetails, target, sn, cfg) == nil
}

// putVerified records email as uuid's verified email, by by, and saves.
// Caller holds s.mu.
func (s *Service) putVerified(uuid, email, by string) error {
	if s.Store == nil {
		return errNoStore()
	}
	if uuid == "" {
		return &Error{Status: http.StatusServiceUnavailable, Msg: "LLDAP gave no account id"}
	}
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}
	setVerified(cfg, uuid, email, by)
	return s.saveConfig(cfg)
}

// setVerified records email as uuid's verified email in cfg (not saved).
func setVerified(cfg *Config, uuid, email, by string) {
	if cfg.EmailVerified == nil {
		cfg.EmailVerified = map[string]EmailVerification{}
	}
	cfg.EmailVerified[uuid] = EmailVerification{Email: strings.TrimSpace(email), At: time.Now().UTC(), By: by}
}

// dropVerified removes uuid's record (if any) and saves. Caller holds
// s.mu.
func (s *Service) dropVerified(uuid string) error {
	if s.Store == nil || uuid == "" {
		return nil
	}
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}
	if _, ok := cfg.EmailVerified[uuid]; !ok {
		return nil
	}
	delete(cfg.EmailVerified, uuid)
	return s.saveConfig(cfg)
}

// emailChanged records what an email change does to the verification
// (UpdateUser, after LLDAP took it): someone else who may verify it
// (mayVerify: edit_details re-checked on sn, never through the AI) sets
// it verified; any other change — your own, the AI's, an emptied email —
// clears it. A failed
// write only logs: the record no longer matching the new email already
// makes it unverified, and an admin's change left unrecorded stays
// unverified (fail closed). Caller holds s.mu.
func (s *Service) emailChanged(c *Caller, sn *snapshot, user, uuid, email string) {
	if s.Store == nil {
		return
	}
	cfg, err := s.loadConfig()
	if err == nil && s.mayVerify(c, user, sn, cfg) && normEmail(email) != "" {
		err = s.putVerified(uuid, email, "admin:"+c.User)
	} else {
		err = s.dropVerified(uuid)
	}
	if err != nil {
		log.Printf("directory: recording %s's email verification: %v", user, err)
	}
}

// MarkEmailVerified is POST /api/directory/users/{u}/email/verified
// (§9.8 case 3): someone holding edit_details on username confirms their
// current email, stored by admin:<caller>; audited user.email_verified.
// Your own email is verified by code only (403); no email is 400.
func (s *Service) MarkEmailVerified(ctx context.Context, c *Caller, username string) error {
	detail := ""
	return s.run(ctx, c, PermEditDetails, "user.email_verified", username, &detail, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if c.Via == ViaAI {
			// Apps trust a verified email: only a person, in the browser.
			return forbidden("not allowed through the AI: mark an email verified on the people page")
		}
		if strings.EqualFold(strings.TrimSpace(c.User), strings.TrimSpace(username)) {
			return forbidden("not allowed: verify your own email with a code")
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if normEmail(u.Email) == "" {
			return invalid("this person has no email")
		}
		detail = "email=" + strings.TrimSpace(u.Email)
		return s.putVerified(u.UUID, u.Email, "admin:"+c.User)
	})
}

// OwnEmail answers user's LLDAP uuid and email (trimmed; "" = none),
// read fresh: the code flow binds a code to both.
func (s *Service) OwnEmail(ctx context.Context, user string) (uuid, email string, err error) {
	if err := s.LLDAP.Available(); err != nil {
		return "", "", &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	if err := s.checkTarget(user); err != nil {
		return "", "", err
	}
	sn, err := s.load(ctx)
	if err != nil {
		return "", "", err
	}
	u, err := sn.user(strings.ToLower(strings.TrimSpace(user)))
	if err != nil {
		return "", "", err
	}
	return u.UUID, strings.TrimSpace(u.Email), nil
}

// VerifyOwnEmail records a's email verified by code (§9.8 case 1),
// audited email.verified. uuid and email are what the code was sent to:
// when the account or its email changed since, nothing is recorded (410,
// the contract's text). The Hub checks the code; this only records.
func (s *Service) VerifyOwnEmail(ctx context.Context, a Actor, uuid, email string) error {
	c := &Caller{User: strings.ToLower(strings.TrimSpace(a.User)), Via: a.Via, Client: a.Client, Confirmation: a.Confirmation}
	detail := "email=" + strings.TrimSpace(email)
	return s.run(ctx, c, permSelf, "email.verified", c.User, &detail, func() error {
		if err := s.checkTarget(c.User); err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(c.User)
		if err != nil {
			return err
		}
		if u.UUID != uuid || normEmail(u.Email) == "" || normEmail(u.Email) != normEmail(email) {
			return &Error{Status: http.StatusGone, Msg: ErrCodeExpiredMsg}
		}
		return s.putVerified(u.UUID, u.Email, ByCode)
	})
}

// uuidOf is user's LLDAP uuid ("" when it can't be read).
func (s *Service) uuidOf(ctx context.Context, user string) string {
	users, err := s.LLDAP.ListUsers(ctx)
	if err != nil {
		return ""
	}
	for _, u := range users {
		if strings.EqualFold(u.ID, user) {
			return u.UUID
		}
	}
	return ""
}
