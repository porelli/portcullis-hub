package hub

import (
	"context"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

// The Hub-side invariants (contract §19.5, §19.6): the Hub never relies
// on the provider's own guards.

// mailMassRemoval reports whether next removes more than half of last's
// accounts (the Hub refuses to send that unless confirmed), and which
// (sorted by username).
func mailMassRemoval(next, last *mailprovider.MailState) (removed []mailprovider.Removed, needs bool) {
	if last == nil || next == nil || len(last.Accounts) == 0 {
		return nil, false
	}
	now := map[string]bool{}
	for _, a := range next.Accounts {
		now[a.UUID] = true
	}
	for _, a := range last.Accounts {
		if !now[a.UUID] {
			removed = append(removed, mailprovider.Removed{Username: a.Username, UUID: a.UUID})
		}
	}
	slices.SortFunc(removed, func(a, b mailprovider.Removed) int {
		if a.Username < b.Username {
			return -1
		}
		if a.Username > b.Username {
			return 1
		}
		return 0
	})
	return removed, len(removed)*2 > len(last.Accounts)
}

// errHubMassRemoval is the Hub's own refusal, shaped as the provider's
// (mailMassRefused handles both).
func errHubMassRemoval(removed []mailprovider.Removed) error {
	return &mailprovider.APIError{Status: http.StatusConflict, Kind: mailprovider.ErrorKindMassRemoval, Removed: removed,
		Msg: "the Hub refused a mass removal: more than half the mailboxes would go at once"}
}

// mailLANOnly is the LAN-only verification's state (doctor
// mail_lan_only_unenforced).
type mailLANOnly struct {
	mu   sync.Mutex
	last time.Time // the last credential found wider than the Local networks
	user string
}

// MailLANOnlyBreach is when (and whose) a credential was last found
// wider than the Local networks under LAN-only (zero: never).
func (h *Hub) MailLANOnlyBreach() (time.Time, string) {
	h.mailLAN.mu.Lock()
	defer h.mailLAN.mu.Unlock()
	return h.mailLAN.last, h.mailLAN.user
}

// mailLocalNetworks are the addresses a LAN-only credential may
// authenticate from: the Local networks, or loopback when there are none
// (contract §19.6).
func (h *Hub) mailLocalNetworks() []netip.Prefix {
	h.mu.RLock()
	ps := h.localNetworksLocked()
	h.mu.RUnlock()
	if len(ps) == 0 {
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	}
	return ps
}

// sameAddressSet: a and b cover exactly the same addresses (a provider
// may split a prefix).
func sameAddressSet(a, b []netip.Prefix) bool {
	ra, rb := addrRanges(a), addrRanges(b)
	if len(ra) != len(rb) {
		return false
	}
	for i := range ra {
		if ra[i][0].Cmp(rb[i][0]) != 0 || ra[i][1].Cmp(rb[i][1]) != 0 {
			return false
		}
	}
	return true
}

// addrRanges are ps as merged, sorted [first, last] ranges over one
// 129-bit space (IPv4 below IPv6, never adjacent: a family bit apart).
func addrRanges(ps []netip.Prefix) [][2]*big.Int {
	var rs [][2]*big.Int
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		a := p.Addr()
		bits, plen := 32, p.Bits()
		base := new(big.Int)
		switch {
		case a.Is4In6() && plen >= 96:
			// ::ffff:a.b.c.d/n is the IPv4 a.b.c.d/(n-96).
			a, plen = a.Unmap(), plen-96
		case a.Is6():
			bits = 128
			base.Lsh(big.NewInt(1), 128) // the IPv6 family above every IPv4
		}
		v := new(big.Int).SetBytes(a.AsSlice())
		first := new(big.Int).Add(base, v)
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-plen))
		last := new(big.Int).Add(first, new(big.Int).Sub(size, big.NewInt(1)))
		rs = append(rs, [2]*big.Int{first, last})
	}
	slices.SortFunc(rs, func(x, y [2]*big.Int) int { return x[0].Cmp(y[0]) })
	var out [][2]*big.Int
	for _, r := range rs {
		if n := len(out); n > 0 && new(big.Int).Add(out[n-1][1], big.NewInt(1)).Cmp(r[0]) >= 0 {
			if r[1].Cmp(out[n-1][1]) > 0 {
				out[n-1][1] = r[1]
			}
			continue
		}
		out = append(out, [2]*big.Int{new(big.Int).Set(r[0]), new(big.Int).Set(r[1])})
	}
	return out
}

// checkAllowedIPs (LAN-only, contract §19.6): every live credential of
// the account whose allowed_ips doesn't cover exactly the Local networks
// is revoked at once (bounded; its row ends revoked, by lan-only, only on
// the provider's word: 204 or 404, M6), the sessions reset and the
// breach kept for the doctor. A revoke the provider doesn't confirm
// leaves the row active and voids the provider (Ruling R-HH2, fail
// closed). Answers how many were wider and the ids revoked. Nothing
// while LAN-only is off.
func (h *Hub) checkAllowedIPs(ctx context.Context, api MailAPI, user, uuid string, live []mailprovider.Credential) (wider int, revoked []string) {
	if !h.mailCore().SubmissionLAN || uuid == "" {
		return 0, nil
	}
	want := h.mailLocalNetworks()
	failed := false
	for _, c := range live {
		if sameAddressSet(c.AllowedIPs, want) {
			continue
		}
		wider++
		h.mailLAN.mu.Lock()
		h.mailLAN.last, h.mailLAN.user = h.mailNow(), user
		h.mailLAN.mu.Unlock()
		log.Printf("mail: %s's mail password %s may authenticate from beyond the Local networks under LAN-only: revoked", user, c.ID)
		if err := h.mailRevokeBounded(ctx, api, uuid, c.ID); err != nil {
			log.Printf("mail: revoking %s's mail password %s (LAN-only): %v", user, c.ID, err)
			failed = true
			continue
		}
		revoked = append(revoked, c.ID)
		h.mailEndRowsOf(user, uuid, c, "lan-only")
	}
	if len(revoked) > 0 {
		h.goBackground(func() { h.mailRestart(context.Background(), "a LAN-only revoke") })
	}
	if failed {
		h.mailFailClosed(user + "'s mail password beyond the Local networks can't be revoked")
	}
	return wider, revoked
}

// mailRevokeBounded revokes one credential within mailCallTimeout (never
// cancelled by the request); nil on the provider's 204 or 404.
func (h *Hub) mailRevokeBounded(ctx context.Context, api MailAPI, uuid, id string) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailCallTimeout)
	defer cancel()
	err := api.RevokeCredential(rctx, uuid, id)
	if mailprovider.StatusOf(err) == http.StatusNotFound {
		return nil
	}
	return err
}

// mailFailClosed voids the wired provider (Ruling R-HH2): a credential
// that must not live can't be removed, so every password goes — a void
// owed (the gate closes at once, void mode at the next up) and the void
// started now. Reason wire: the provider's own store is untrusted.
func (h *Hub) mailFailClosed(why string) {
	h.mu.Lock()
	p := h.st.Mail.Provider
	var err error
	if p != nil {
		err = h.markVoidOwedLocked(state.MailVoidWire)
	}
	h.mu.Unlock()
	if p == nil {
		return
	}
	log.Printf("mail: %s: voiding the provider %s (fail closed)", why, p.Instance)
	if err != nil {
		log.Printf("mail: recording the void of %s: %v", p.Instance, err)
	}
	h.writeMailTargets()
	h.kickMailVoid()
}

// mailEndRowsOf ends the active row standing for live credential c.
func (h *Hub) mailEndRowsOf(user, uuid string, c mailprovider.Credential, by string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rows := h.st.MailCredentials[user]
	now := h.mailNow().UTC()
	changed := false
	for i := range rows {
		r := &rows[i]
		if r.Active() && r.UUID == uuid && r.StalwartID == c.ID && r.CreatedAt.Equal(c.CreatedAt.UTC()) {
			r.RevokedAt, r.Reason, r.RevokedBy = &now, state.MailCredentialReasonRevoked, by
			changed = true
		}
	}
	if changed {
		h.saveLocked()
	}
}
