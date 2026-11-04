package hub

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor (contract §14.5): the Hub gathers a snapshot of its state
// (doctorInputs), internal/doctor judges it. The doctor never changes
// anything; mutes are the only thing it stores.

// muteReasonMax is a mute reason's limit in characters.
const muteReasonMax = 200

// Doctor runs every registered check on the current configuration
// (enabled instances) with the stored mutes applied. 503 without Users
// & Groups (contract §14).
func (h *Hub) Doctor(ctx context.Context) (*doctor.Report, error) {
	h.mu.RLock()
	noPeople := h.people == nil
	h.mu.RUnlock()
	if noPeople {
		return nil, statusErr(http.StatusServiceUnavailable, "users & groups is not available")
	}
	in, err := h.doctorInputs(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	mutes := make(map[string]doctor.Mute, len(h.st.DoctorMutes))
	for fp, m := range h.st.DoctorMutes {
		mutes[fp] = doctor.Mute{Reason: m.Reason, Actor: m.Actor, At: m.At, Inputs: m.Inputs}
	}
	h.mu.RUnlock()
	r := doctor.Run(in, mutes)
	return &r, nil
}

// pathIn is u as the doctor reads it (field by field: TestPathInCopiesEveryField).
func pathIn(u PathUsage) doctor.PathIn {
	return doctor.PathIn{
		Instance: u.Instance, Key: u.Key, Label: u.Label, HostPath: u.HostPath, Service: u.Service, Mount: u.Mount,
		Access: u.Access, Source: u.Source, Folder: u.Folder, Subpath: u.Subpath, JoinsGroup: u.JoinsGroup,
		UIDEnv: u.UIDEnv, GIDEnv: u.GIDEnv, UID: u.UID, GID: u.GID, GIDs: slices.Clone(u.GIDs),
		OwnerKnown: u.OwnerKnown, Writes: u.Writes, ReadOnly: u.ReadOnly, MustOwn: u.MustOwn, Declared: u.Declared,
		Checks: slices.Clone(u.Checks),
	}
}

// doctorInputs gathers the doctor's inputs: the directory snapshot first
// (never under mu; unavailable = per-person rows not judged by
// membership) and the main domain's addresses (domainAddrs: cached, 2 s
// timeout; a failure = DomainErr, nothing escalates), then a copy of the
// state under the read lock: paths, folders, folder_changed records,
// per-person options, published ports (portInsLocked) and the local
// networks, and the cached disk scans of the current targets with the
// enabled instances' container gids (doctorscan.go).
func (h *Hub) doctorInputs(ctx context.Context) (*doctor.Inputs, error) {
	h.mu.RLock()
	people := h.people
	h.mu.RUnlock()
	var m *directory.Membership
	if people != nil {
		var err error
		if m, err = people.Membership(ctx, time.Now().UTC()); err != nil {
			log.Printf("doctor: the directory is unavailable (%v): per-person rows not judged", err)
			m = nil
		}
	}
	// The disk scans' cache (Task 11), read before mu (a leaf lock; the
	// file is loaded on first use).
	scans, rt := h.scanEntries(), h.scanRuntime()
	addrs, derr := h.domainAddrs(ctx)
	if derr != nil {
		log.Printf("doctor: couldn't resolve %s (%v): exposure not checked against its addresses", h.cfg.Domain, derr)
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	in := &doctor.Inputs{Now: time.Now().UTC(), BindRoots: slices.Clone(h.bindRoots),
		Domain: h.cfg.Domain, DomainAddrs: addrs, DomainErr: derr != nil,
		LocalNetworks: h.localNetworksLocked(), Ports: h.portInsLocked()}
	for _, u := range h.pathUsagesLocked() {
		in.Paths = append(in.Paths, pathIn(u))
	}
	in.Scans, in.Runtime = h.doctorScansLocked(scans, rt)
	ids := make([]string, 0, len(h.st.Folders))
	for id := range h.st.Folders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f := h.st.Folders[id]
		fi := doctor.FolderIn{ID: id, Name: f.Name, Path: f.Path, GID: f.GID}
		if f.LastApply != nil {
			at := f.LastApply.At
			fi.LastApply = &at
		}
		for _, p := range in.Paths {
			if p.Folder == id {
				fi.Uses = append(fi.Uses, p)
			}
		}
		in.Folders = append(in.Folders, fi)
	}
	// folder_changed records: the instance was taken down (often left
	// disabled by the refused enable), so they are judged whatever its
	// enabled flag.
	for _, l := range h.st.FolderChanged {
		for _, c := range l {
			in.Changes = append(in.Changes, doctor.ChangeIn{Instance: c.Instance, Key: c.Key, Folder: c.Folder, Subpath: c.Subpath, Detail: c.Detail, At: c.At})
		}
	}
	sort.Slice(in.Changes, func(i, j int) bool {
		if in.Changes[i].Instance != in.Changes[j].Instance {
			return in.Changes[i].Instance < in.Changes[j].Instance
		}
		return in.Changes[i].Key < in.Changes[j].Key
	})
	for i := range h.instances {
		t := &h.instances[i]
		if !h.st.IsEnabled(t.ID) {
			continue
		}
		in.Person = append(in.Person, h.personInputsLocked(t, m)...)
	}
	return in, nil
}

// personInputsLocked are t's per-person options with their bound rows
// (unbound placeholder rows grant nothing and are left out, plan 1 P7);
// m nil: Exists true and Members -1 (unknown). Caller holds mu (read).
func (h *Hub) personInputsLocked(t *templates.Template, m *directory.Membership) []doctor.PersonIn {
	var out []doctor.PersonIn
	var pop *Population
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopePerson {
			continue
		}
		if m != nil && pop == nil {
			p := h.populationLocked(t, m)
			pop = &p
		}
		pc := h.personConfigLocked(t, o.Key)
		pi := doctor.PersonIn{Instance: t.ID, Key: o.Key, Label: o.Label}
		if pc.Default != nil && o.Type != templates.TypeSecret {
			pi.DefaultDisplay = h.kinds.Display(o, pc.Default)
		}
		for _, c := range o.Checks {
			if c.Kind == templates.CheckRequiresGroupValue {
				c := c
				pi.Requires = &c
			}
		}
		for _, r := range pc.Rows {
			ri := doctor.RowIn{Group: r.Group, GroupID: r.GroupID, Exists: true, Members: -1}
			if m != nil {
				g, ok := m.Groups[r.Group]
				ri.Exists = ok && g.ID == r.GroupID
				ri.Members = 0
				if ri.Exists {
					for _, p := range pop.People {
						if p.Groups[r.Group] == r.GroupID {
							ri.Members++
						}
					}
				}
			}
			pi.Rows = append(pi.Rows, ri)
		}
		out = append(out, pi)
	}
	return out
}

// MuteFinding mutes the current finding fp with reason (non-empty, at
// most 200 characters, one line): 400 / 404 for an unknown fp. token is
// the finding's token as the admin saw it (required, 400): another
// current token is 409, the finding changed since (H8: a mute never hides
// a finding the admin didn't see). The mute keeps the finding's inputs
// digest: it lapses when they change. Audited doctor.mute (detail: the
// reason).
func (h *Hub) MuteFinding(ctx context.Context, fp, reason, actor, token string) error {
	err := h.muteFinding(ctx, fp, reason, actor, token)
	h.auditDoctor(actor, "doctor.mute", fp, firstRunes(strings.TrimSpace(reason), muteReasonMax), err)
	return err
}

func (h *Hub) muteFinding(ctx context.Context, fp, reason, actor, token string) error {
	reason = strings.TrimSpace(reason)
	switch {
	case actor == "":
		return statusErr(http.StatusUnauthorized, "a mute needs a signed-in admin")
	case reason == "":
		return statusErr(http.StatusBadRequest, "a mute needs a reason")
	case utf8.RuneCountInString(reason) > muteReasonMax:
		return statusErr(http.StatusBadRequest, "the reason is longer than %d characters", muteReasonMax)
	case templates.HasControlChars(reason) || !utf8.ValidString(reason):
		return statusErr(http.StatusBadRequest, "the reason must be one line of text")
	case token == "":
		return statusErr(http.StatusBadRequest, "a mute needs the finding's token (from the doctor's report)")
	}
	r, err := h.Doctor(ctx)
	if err != nil {
		return err
	}
	var found *doctor.Finding
	for i := range r.Findings {
		if r.Findings[i].FP == fp {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		return statusErr(http.StatusNotFound, "no finding %s", clip(fp, 32))
	}
	if subtle.ConstantTimeCompare([]byte(found.Token), []byte(token)) != 1 {
		return statusErr(http.StatusConflict, "the finding changed since you saw it: run the doctor again and check it before muting")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, had := h.st.DoctorMutes[fp]
	if h.st.DoctorMutes == nil {
		h.st.DoctorMutes = map[string]state.DoctorMute{}
	}
	h.st.DoctorMutes[fp] = state.DoctorMute{Reason: reason, Actor: actor, At: time.Now().UTC(), Inputs: found.Inputs}
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.DoctorMutes[fp] = prev
		} else {
			delete(h.st.DoctorMutes, fp)
		}
		return err
	}
	return nil
}

// UnmuteFinding removes fp's mute (404 when it has none). Audited
// doctor.unmute.
func (h *Hub) UnmuteFinding(fp, actor string) error {
	var err error
	if actor == "" {
		err = statusErr(http.StatusUnauthorized, "an unmute needs a signed-in admin")
	} else {
		err = h.unmuteFinding(fp)
	}
	h.auditDoctor(actor, "doctor.unmute", fp, "", err)
	return err
}

func (h *Hub) unmuteFinding(fp string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, ok := h.st.DoctorMutes[fp]
	if !ok {
		return statusErr(http.StatusNotFound, "finding %s isn't muted", clip(fp, 32))
	}
	delete(h.st.DoctorMutes, fp)
	if err := h.saveStateLocked(); err != nil {
		h.st.DoctorMutes[fp] = prev
		return err
	}
	return nil
}

// auditDoctor writes a doctor.* audit entry (after mu; refusals
// "refused").
func (h *Hub) auditDoctor(actor, action, fp, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor, Action: action, Target: clip(fp, 32), Detail: detail, Result: "ok"}
	if err != nil {
		e.Result, e.Error = "error", err.Error()
		var se *StatusError
		if errors.As(err, &se) && se.Status < 500 {
			e.Result = "refused"
		}
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}

// firstRunes is s's first n characters.
func firstRunes(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}
