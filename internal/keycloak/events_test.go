package keycloak_test

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestEnsureEventsConfigKeepsListeners (contract §8 "Keycloak's events
// config"): the Hub writes eventsEnabled, the two event types and the
// expiration, and keeps the listeners and every other field as read; an
// equal config isn't written again.
func TestEnsureEventsConfigKeepsListeners(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.With(func() {
		kc.EventsConfig = map[string]any{"eventsEnabled": false, "eventsListeners": []any{"jboss-logging", "x"},
			"enabledEventTypes": []any{"REGISTER"}, "adminEventsEnabled": true, "adminEventsDetailsEnabled": true}
	})
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	kc.With(func() { got = kc.EventsConfig })
	want := map[string]any{"eventsEnabled": true, "eventsListeners": []any{"jboss-logging", "x"},
		"enabledEventTypes": []any{"LOGIN", "LOGIN_ERROR", "IMPERSONATE"}, "eventsExpiration": float64(90 * 86400),
		"adminEventsEnabled": true, "adminEventsDetailsEnabled": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events config = %v\nwant %v", got, want)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("%d PUTs, want 1", n)
	}
	// Already right: read, not written.
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("an equal config was written again (%d PUTs)", n)
	}
	// Keycloak answers the types in another order (it keeps a set): still
	// the same config, not written.
	kc.With(func() { kc.EventsConfig["enabledEventTypes"] = []any{"IMPERSONATE", "LOGIN_ERROR", "LOGIN"} })
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("the same types in another order were written again (%d PUTs)", n)
	}
	// A new history length is written.
	if err := c.EnsureEventsConfig(ctx, 365); err != nil {
		t.Fatal(err)
	}
	kc.With(func() { got = kc.EventsConfig })
	if got["eventsExpiration"] != float64(365*86400) || !reflect.DeepEqual(got["eventsListeners"], []any{"jboss-logging", "x"}) {
		t.Errorf("after 365: %v", got)
	}
	// Refusals: no history length; Keycloak failing.
	if err := c.EnsureEventsConfig(ctx, 0); err == nil {
		t.Error("0 days accepted")
	}
	kc.SetFailPrefix("PUT /admin/realms/portcullis/events")
	if err := c.EnsureEventsConfig(ctx, 30); err == nil {
		t.Error("a failed PUT was not reported")
	}
	kc.SetFailPrefix("GET /admin/realms/portcullis/events")
	if err := c.EnsureEventsConfig(ctx, 30); err == nil {
		t.Error("a failed GET was not reported")
	}
}

// TestEventsConfigHasImpersonate (D44, F4): EnsureEventsConfig stores
// ConfigEventTypes = {LOGIN, LOGIN_ERROR, IMPERSONATE}, compared as a set:
// the part-2 config (no IMPERSONATE) is written again.
func TestEventsConfigHasImpersonate(t *testing.T) {
	ctx := context.Background()
	if want := []string{"LOGIN", "LOGIN_ERROR", "IMPERSONATE"}; !reflect.DeepEqual(keycloak.ConfigEventTypes, want) {
		t.Fatalf("ConfigEventTypes = %v, want %v", keycloak.ConfigEventTypes, want)
	}
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.With(func() {
		kc.EventsConfig = map[string]any{"eventsEnabled": true, "enabledEventTypes": []any{"LOGIN", "LOGIN_ERROR"},
			"eventsExpiration": float64(90 * 86400)}
	})
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	var got any
	kc.With(func() { got = kc.EventsConfig["enabledEventTypes"] })
	if !reflect.DeepEqual(got, []any{"LOGIN", "LOGIN_ERROR", "IMPERSONATE"}) {
		t.Errorf("enabledEventTypes = %v", got)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("%d PUTs, want 1 (the part-2 config lacks IMPERSONATE)", n)
	}
	// A set: duplicates and order don't matter.
	kc.With(func() { kc.EventsConfig["enabledEventTypes"] = []any{"LOGIN_ERROR", "IMPERSONATE", "LOGIN", "LOGIN"} })
	if err := c.EnsureEventsConfig(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if n := kc.CountCalls("PUT /admin/realms/portcullis/events/config"); n != 1 {
		t.Errorf("the same set was written again (%d PUTs)", n)
	}
}

// TestHistoryQueryUnchanged (F4): the history query still asks for
// type=LOGIN&type=LOGIN_ERROR only (HistoryEventTypes), never IMPERSONATE.
func TestHistoryQueryUnchanged(t *testing.T) {
	if want := []string{"LOGIN", "LOGIN_ERROR"}; !reflect.DeepEqual(keycloak.HistoryEventTypes, want) {
		t.Fatalf("HistoryEventTypes = %v, want %v", keycloak.HistoryEventTypes, want)
	}
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	alice := kc.Import("alice")
	now := time.Now().UTC()
	if _, err := c.LoginEventsPage(ctx, alice.ID, now.Add(-time.Hour), now, 0, 5); err != nil {
		t.Fatal(err)
	}
	var q url.Values
	kc.With(func() { q = kc.EventsQuery })
	if !reflect.DeepEqual(q["type"], []string{"LOGIN", "LOGIN_ERROR"}) {
		t.Errorf("types = %v", q["type"])
	}
}

// TestLoginEventsQuery (contract §8.2): LoginEvents asks for the user's
// LOGIN and LOGIN_ERROR events of the days from..to, at most max, and
// decodes the details.
func TestLoginEventsQuery(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	alice := kc.Import("alice")
	at := time.Date(2026, 11, 10, 8, 14, 2, 0, time.UTC)
	kc.With(func() {
		kc.Events = []map[string]any{
			{"time": at.UnixMilli(), "type": "LOGIN", "clientId": "portcullis-forward-auth", "userId": alice.ID, "ipAddress": "203.0.113.7",
				"details": map[string]any{"pc_kind": "sign_in", "pc_methods": "security_key", "pc_session": "security_key", "pc_ua": "Firefox"}},
			{"time": at.Add(-time.Hour).UnixMilli(), "type": "LOGIN_ERROR", "clientId": "portcullis-forward-auth", "userId": alice.ID,
				"error": "invalid_user_credentials", "details": map[string]any{"pc_method": "password"}},
			{"time": at.UnixMilli(), "type": "LOGIN", "userId": "someone-else"},
		}
	})
	from, to := at.AddDate(0, 0, -30), at.Add(time.Second)
	evs, err := c.LoginEvents(ctx, alice.ID, from, to, 51)
	if err != nil {
		t.Fatal(err)
	}
	var q url.Values
	kc.With(func() { q = kc.EventsQuery })
	if q.Get("user") != alice.ID || !reflect.DeepEqual(q["type"], []string{"LOGIN", "LOGIN_ERROR"}) ||
		q.Get("dateFrom") != fmt.Sprint(from.UnixMilli()) || q.Get("dateTo") != fmt.Sprint(to.UnixMilli()-1) || q.Get("max") != "51" || q.Has("first") {
		t.Errorf("query = %v", q)
	}
	if n := kc.CountCalls("GET /admin/realms/portcullis/events"); n != 1 {
		t.Errorf("%d event reads", n)
	}
	want := []keycloak.Event{
		{Time: at, Type: "LOGIN", ClientID: "portcullis-forward-auth", UserID: alice.ID, IP: "203.0.113.7",
			Details: map[string]string{"pc_kind": "sign_in", "pc_methods": "security_key", "pc_session": "security_key", "pc_ua": "Firefox"}},
		{Time: at.Add(-time.Hour), Type: "LOGIN_ERROR", ClientID: "portcullis-forward-auth", UserID: alice.ID,
			Error: "invalid_user_credentials", Details: map[string]string{"pc_method": "password"}},
	}
	if !reflect.DeepEqual(evs, want) {
		t.Errorf("events = %+v\nwant %+v", evs, want)
	}
	// By username, paged; an unknown user has none.
	evs, err = c.UserLoginEventsPage(ctx, "alice", from, to, 1, 5)
	if err != nil || len(evs) != 1 || evs[0].Type != "LOGIN_ERROR" {
		t.Errorf("page 2 = %+v, %v", evs, err)
	}
	kc.With(func() { q = kc.EventsQuery })
	if q.Get("first") != "1" || q.Get("max") != "5" {
		t.Errorf("paged query = %v", q)
	}
	if evs, err := c.UserLoginEventsPage(ctx, "nobody", from, to, 0, 5); err != nil || len(evs) != 0 {
		t.Errorf("unknown user: %+v, %v", evs, err)
	}
	if _, err := c.LoginEvents(ctx, "not-an-id", from, to, 5); err == nil {
		t.Error("a bad user id was queried")
	}
	kc.SetFailPrefix("GET /admin/realms/portcullis/events")
	if _, err := c.LoginEvents(ctx, alice.ID, from, to, 5); err == nil {
		t.Error("a failed read was not reported")
	}
}

// TestImpersonateEventsQuery (F4): ImpersonateEvents asks for
// type=IMPERSONATE only, for the person, in the window, and pages.
func TestImpersonateEventsQuery(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	alice := kc.Import("alice")
	at := time.Date(2026, 11, 12, 14, 3, 0, 0, time.UTC)
	kc.With(func() {
		kc.Events = []map[string]any{
			{"time": at.UnixMilli(), "type": "IMPERSONATE", "clientId": "portcullis-forward-auth", "userId": alice.ID,
				"details": map[string]any{"pc_imp": "0f3c0f3c0f3c0f3c0f3c0f3c0f3c0f3c", "pc_act": "root"}},
			{"time": at.UnixMilli(), "type": "LOGIN", "userId": alice.ID},
		}
		for i := range 150 {
			kc.Events = append(kc.Events, map[string]any{"time": at.Add(-time.Duration(i+1) * time.Second).UnixMilli(), "type": "IMPERSONATE", "userId": alice.ID})
		}
	})
	from, to := at.Add(-time.Hour), at.Add(time.Second)
	evs, err := c.ImpersonateEvents(ctx, alice.ID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	var q url.Values
	kc.With(func() { q = kc.EventsQuery })
	if q.Get("user") != alice.ID || !reflect.DeepEqual(q["type"], []string{"IMPERSONATE"}) ||
		q.Get("dateFrom") != fmt.Sprint(from.UnixMilli()) || q.Get("dateTo") != fmt.Sprint(to.UnixMilli()-1) || q.Get("first") != "100" {
		t.Errorf("query = %v", q)
	}
	if len(evs) != 151 || evs[0].Type != "IMPERSONATE" || evs[0].Details["pc_imp"] != "0f3c0f3c0f3c0f3c0f3c0f3c0f3c0f3c" || evs[0].Details["pc_act"] != "root" {
		t.Errorf("events = %d, first %+v", len(evs), evs[0])
	}
	if n := kc.CountCalls("GET /admin/realms/portcullis/events"); n != 2 {
		t.Errorf("%d event reads", n)
	}
	if evs, err := c.UserImpersonateEvents(ctx, "nobody", from, to); err != nil || len(evs) != 0 {
		t.Errorf("unknown user = %v, %v", evs, err)
	}
	if evs, err := c.UserImpersonateEvents(ctx, "alice", from, to); err != nil || len(evs) != 151 {
		t.Errorf("alice by name = %d, %v", len(evs), err)
	}
}

// TestClientLoginEventsQuery: the native-apps read is narrowed server
// side to type=LOGIN and the one client.
func TestClientLoginEventsQuery(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	alice := kc.Import("alice")
	at := time.Date(2026, 11, 12, 14, 3, 0, 0, time.UTC)
	kc.With(func() {
		kc.Events = []map[string]any{
			{"time": at.UnixMilli(), "type": "LOGIN", "clientId": "nextcloud", "userId": alice.ID, "details": map[string]any{"pc_act": "root"}},
			{"time": at.UnixMilli(), "type": "LOGIN", "clientId": "portcullis-forward-auth", "userId": alice.ID},
			{"time": at.UnixMilli(), "type": "LOGIN_ERROR", "clientId": "nextcloud", "userId": alice.ID},
		}
	})
	evs, err := c.UserClientLoginEvents(ctx, "alice", "nextcloud", at.Add(-time.Hour), at.Add(time.Second), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var q url.Values
	kc.With(func() { q = kc.EventsQuery })
	if q.Get("client") != "nextcloud" || !reflect.DeepEqual(q["type"], []string{"LOGIN"}) || q.Get("user") != alice.ID || q.Get("max") != "100" {
		t.Errorf("query = %v", q)
	}
	if len(evs) != 1 || evs[0].ClientID != "nextcloud" || evs[0].Details["pc_act"] != "root" {
		t.Errorf("events = %+v", evs)
	}
	if _, err := c.UserClientLoginEvents(ctx, "alice", "", at, at, 0, 1); err == nil {
		t.Error("no client accepted")
	}
}
