package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// ConfigEventTypes are the user events the Hub has Keycloak store
// (contract §8 "Keycloak's events config", compared as a set): the sign-in
// history's source (§8.2) and the impersonation start (§8.1).
var ConfigEventTypes = []string{"LOGIN", "LOGIN_ERROR", "IMPERSONATE"}

// HistoryEventTypes are the types the sign-in history reads
// (LoginEventsPage, §8.2: the query is unchanged by part 3).
var HistoryEventTypes = []string{"LOGIN", "LOGIN_ERROR"}

// eventsConfigPath is the realm's events config.
func (c *Client) eventsConfigPath() string {
	return c.BaseURL + "/admin/realms/" + Realm + "/events/config"
}

// EnsureEventsConfig makes the realm store LOGIN, LOGIN_ERROR and IMPERSONATE events
// for historyDays days (contract §8 "Keycloak's events config"): it reads
// the config and, when it differs, writes it back with eventsEnabled true,
// enabledEventTypes ConfigEventTypes and eventsExpiration
// historyDays × 86400 seconds. Every other field — eventsListeners and
// the admin-events switches included — is written back as it was read.
func (c *Client) EnsureEventsConfig(ctx context.Context, historyDays int) error {
	if historyDays < 1 {
		return fmt.Errorf("events config: history of %d days", historyDays)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).Get(c.eventsConfigPath())
	if err != nil {
		return fmt.Errorf("read the events config: %w", err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "read the events config", Status: resp.StatusCode()}
	}
	cfg := map[string]json.RawMessage{}
	if err := json.Unmarshal(resp.Body(), &cfg); err != nil || cfg == nil {
		return fmt.Errorf("read the events config: not a JSON object")
	}
	var cur struct {
		Enabled    bool     `json:"eventsEnabled"`
		Types      []string `json:"enabledEventTypes"`
		Expiration int64    `json:"eventsExpiration"`
	}
	// A field of another type just counts as different.
	_ = json.Unmarshal(resp.Body(), &cur)
	want := int64(historyDays) * 86400
	// Keycloak keeps the types as a set: any order is the same config.
	types := slices.Clone(cur.Types)
	slices.Sort(types)
	types = slices.Compact(types)
	wantTypes := slices.Clone(ConfigEventTypes)
	slices.Sort(wantTypes)
	if cur.Enabled && slices.Equal(types, wantTypes) && cur.Expiration == want {
		return nil
	}
	cfg["eventsEnabled"] = json.RawMessage("true")
	typesJSON, _ := json.Marshal(ConfigEventTypes)
	cfg["enabledEventTypes"] = typesJSON
	cfg["eventsExpiration"] = json.RawMessage(fmt.Sprint(want))
	resp, err = c.api().GetRequestWithBearerAuth(ctx, tok).SetBody(cfg).Put(c.eventsConfigPath())
	if err != nil {
		return fmt.Errorf("write the events config: %w", err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "write the events config", Status: resp.StatusCode()}
	}
	return nil
}

// Event is one of the realm's user events as the history reads it
// (contract §8.2): LOGIN and LOGIN_ERROR, with the extension's pc_*
// details (§8.1 "History details").
type Event struct {
	Time     time.Time
	Type     string
	ClientID string
	UserID   string
	IP       string
	Error    string
	Details  map[string]string
}

// eventRep is Keycloak's EventRepresentation (time in epoch ms).
type eventRep struct {
	Time      int64             `json:"time"`
	Type      string            `json:"type"`
	ClientID  string            `json:"clientId"`
	UserID    string            `json:"userId"`
	IPAddress string            `json:"ipAddress"`
	Error     string            `json:"error"`
	Details   map[string]string `json:"details"`
}

// LoginEvents reads userID's LOGIN and LOGIN_ERROR events with from <=
// time < to (contract §8.2: GET …/events?user=&type=LOGIN&type=LOGIN_ERROR&
// dateFrom=&dateTo=&max=), newest first as Keycloak answers them, at most
// max. dateFrom and dateTo are epoch milliseconds (Keycloak 26 reads a
// number as a time, both inclusive): from rounded up, to − 1 ns rounded
// down, so the window is exact and needs no time zone.
func (c *Client) LoginEvents(ctx context.Context, userID string, from, to time.Time, max int) ([]Event, error) {
	return c.LoginEventsPage(ctx, userID, from, to, 0, max)
}

// LoginEventsPage is LoginEvents from the first-th event on (Keycloak's
// first): the history pages through the events newer than its window.
func (c *Client) LoginEventsPage(ctx context.Context, userID string, from, to time.Time, first, max int) ([]Event, error) {
	return c.eventsPage(ctx, "login events", HistoryEventTypes, userID, from, to, first, max)
}

// impersonateEventsPage and impersonateEventsPages bound ImpersonateEvents'
// read: pages of 100, at most 10 (an impersonation window is 30 minutes).
const (
	impersonateEventsPage  = 100
	impersonateEventsPages = 10
)

// ImpersonateEvents reads userID's IMPERSONATE events (the person's: the
// extension's start sends it with user = the person and the details
// pc_imp = the id, pc_act = the administrator; contract §8.1) with from
// <= time < to, newest first: type=IMPERSONATE only (F4: the history
// query stays LOGIN and LOGIN_ERROR). More than the read's bound is an
// error (the caller then counts the impersonation as used).
func (c *Client) ImpersonateEvents(ctx context.Context, userID string, from, to time.Time) ([]Event, error) {
	out := []Event{}
	for page := 0; page < impersonateEventsPages; page++ {
		evs, err := c.eventsPage(ctx, "impersonate events", []string{"IMPERSONATE"}, userID, from, to, len(out), impersonateEventsPage)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
		if len(evs) < impersonateEventsPage {
			return out, nil
		}
	}
	return nil, fmt.Errorf("impersonate events: more than %d", impersonateEventsPage*impersonateEventsPages)
}

// UserImpersonateEvents is ImpersonateEvents for a username: a user
// Keycloak doesn't know has no events.
func (c *Client) UserImpersonateEvents(ctx context.Context, username string, from, to time.Time) ([]Event, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return []Event{}, nil
	}
	return c.ImpersonateEvents(ctx, str(u.ID), from, to)
}

// eventsPage reads userID's events of types with from <= time < to, from
// the first-th on, at most max (what names the read in errors).
func (c *Client) eventsPage(ctx context.Context, what string, types []string, userID string, from, to time.Time, first, max int) ([]Event, error) {
	if !ValidUserID(userID) {
		return nil, fmt.Errorf("%s: not a Keycloak user id", what)
	}
	if max < 1 || first < 0 {
		return nil, fmt.Errorf("%s: first %d, max %d", what, first, max)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("user", userID)
	for _, t := range types {
		q.Add("type", t)
	}
	q.Set("dateFrom", strconv.FormatInt(ceilMilli(from), 10))
	q.Set("dateTo", strconv.FormatInt(to.Add(-time.Nanosecond).UnixMilli(), 10))
	if first > 0 {
		q.Set("first", strconv.Itoa(first))
	}
	q.Set("max", strconv.Itoa(max))
	var reps []eventRep
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&reps).
		Get(c.BaseURL + "/admin/realms/" + Realm + "/events?" + q.Encode())
	if err != nil {
		return nil, fmt.Errorf("read the %s: %w", what, err)
	}
	if resp.IsError() {
		return nil, &HTTPError{Op: "read the " + what, Status: resp.StatusCode()}
	}
	out := make([]Event, 0, len(reps))
	for _, r := range reps {
		d := r.Details
		if d == nil {
			d = map[string]string{}
		}
		out = append(out, Event{Time: time.UnixMilli(r.Time).UTC(), Type: r.Type, ClientID: r.ClientID,
			UserID: r.UserID, IP: r.IPAddress, Error: r.Error, Details: d})
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// ceilMilli is t in epoch milliseconds, rounded up.
func ceilMilli(t time.Time) int64 {
	ms := t.UnixMilli()
	if time.UnixMilli(ms).Before(t) {
		ms++
	}
	return ms
}

// UserLoginEventsPage is LoginEventsPage for a username: a user Keycloak
// doesn't know has no events.
func (c *Client) UserLoginEventsPage(ctx context.Context, username string, from, to time.Time, first, max int) ([]Event, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return []Event{}, nil
	}
	return c.LoginEventsPage(ctx, str(u.ID), from, to, first, max)
}
