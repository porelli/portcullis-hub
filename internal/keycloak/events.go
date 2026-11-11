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

// EventTypes are the user events the Hub has Keycloak store (contract §8
// "Keycloak's events config"): the sign-in history's source (§8.2).
var EventTypes = []string{"LOGIN", "LOGIN_ERROR"}

// eventsConfigPath is the realm's events config.
func (c *Client) eventsConfigPath() string {
	return c.BaseURL + "/admin/realms/" + Realm + "/events/config"
}

// EnsureEventsConfig makes the realm store LOGIN and LOGIN_ERROR events
// for historyDays days (contract §8 "Keycloak's events config"): it reads
// the config and, when it differs, writes it back with eventsEnabled true,
// enabledEventTypes [LOGIN, LOGIN_ERROR] and eventsExpiration
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
	wantTypes := slices.Clone(EventTypes)
	slices.Sort(wantTypes)
	if cur.Enabled && slices.Equal(types, wantTypes) && cur.Expiration == want {
		return nil
	}
	cfg["eventsEnabled"] = json.RawMessage("true")
	typesJSON, _ := json.Marshal(EventTypes)
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

// eventsDay is the date format of the events query's dateFrom / dateTo.
const eventsDay = "2006-01-02"

// LoginEvents reads userID's LOGIN and LOGIN_ERROR events from the day of
// from to the day of to (contract §8.2: GET …/events?user=&type=LOGIN&
// type=LOGIN_ERROR&dateFrom=&dateTo=&max=), newest first as Keycloak
// answers them, at most max. The days are whole UTC days and Keycloak may
// read them in its own zone: callers filter by time.
func (c *Client) LoginEvents(ctx context.Context, userID string, from, to time.Time, max int) ([]Event, error) {
	return c.LoginEventsPage(ctx, userID, from, to, 0, max)
}

// LoginEventsPage is LoginEvents from the first-th event on (Keycloak's
// first): the history pages through the events newer than its window.
func (c *Client) LoginEventsPage(ctx context.Context, userID string, from, to time.Time, first, max int) ([]Event, error) {
	if !ValidUserID(userID) {
		return nil, fmt.Errorf("login events: not a Keycloak user id")
	}
	if max < 1 || first < 0 {
		return nil, fmt.Errorf("login events: first %d, max %d", first, max)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("user", userID)
	for _, t := range EventTypes {
		q.Add("type", t)
	}
	q.Set("dateFrom", from.UTC().Format(eventsDay))
	q.Set("dateTo", to.UTC().Format(eventsDay))
	if first > 0 {
		q.Set("first", strconv.Itoa(first))
	}
	q.Set("max", strconv.Itoa(max))
	var reps []eventRep
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&reps).
		Get(c.BaseURL + "/admin/realms/" + Realm + "/events?" + q.Encode())
	if err != nil {
		return nil, fmt.Errorf("read the login events: %w", err)
	}
	if resp.IsError() {
		return nil, &HTTPError{Op: "read the login events", Status: resp.StatusCode()}
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
