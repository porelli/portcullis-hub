package hub

import (
	"errors"
	"strings"
	"testing"
)

func TestCreateInstanceAsGroups(t *testing.T) {
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	g := &fakeGroups{}
	f.h.SetGroups(g)

	res, err := f.h.CreateInstanceAs("grafana", "grafana-team-a", nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateCreated || res.Hosts["grafana"] != "grafana-team-a.example.org" || res.AccessGroup != "users_grafana-team-a" {
		t.Errorf("result = %+v", res)
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_grafana-team-a:alice,+admin_grafana-team-a:alice" {
		t.Errorf("groups = %s", got)
	}
	if e := audit.last(); e.Action != "instance.create" || e.Result != "ok" || e.Actor != "alice" || e.Target != "grafana-team-a" ||
		!strings.Contains(e.Detail, "template=grafana") || !strings.Contains(e.Detail, "grafana=grafana-team-a.example.org") {
		t.Errorf("audit = %+v", e)
	}

	// The actor must resolve first: nothing is created.
	g.actorErr = errors.New("not an administrator")
	if _, err := f.h.CreateInstanceAs("grafana", "grafana-b", nil, "dana"); err == nil || !strings.Contains(err.Error(), "nothing was created") {
		t.Fatalf("actor = %v", err)
	}
	if _, ok := f.h.InstanceView("grafana-b"); ok {
		t.Error("created despite the actor")
	}
	if e := audit.last(); e.Result != "error" || e.Actor != "dana" {
		t.Errorf("audit = %+v", e)
	}
	g.actorErr = nil

	// A failing group: the instance and the groups created so far go again.
	g.createErr = func(name string) error {
		if strings.HasPrefix(name, "admin_") {
			return errors.New("lldap down")
		}
		return nil
	}
	_, err = f.h.CreateInstanceAs("grafana", "grafana-c", nil, "alice")
	if err == nil || !strings.Contains(err.Error(), "removed again") {
		t.Fatalf("group failure = %v", err)
	}
	if _, ok := f.h.InstanceView("grafana-c"); ok {
		t.Error("instance kept after a group failure")
	}
	if got := strings.Join(g.Calls(), ","); !strings.HasSuffix(got, "+users_grafana-c:alice,-users_grafana-c:alice") {
		t.Errorf("groups = %s", got)
	}
	// The id is free again.
	g.createErr = nil
	if _, err := f.h.CreateInstanceAs("grafana", "grafana-c", nil, "alice"); err != nil {
		t.Fatal(err)
	}

	// No actor, a single template: refused.
	if _, err := f.h.CreateInstanceAs("grafana", "grafana-d", nil, ""); statusOf(err) != 400 {
		t.Errorf("no actor = %v", err)
	}
	if _, err := f.h.CreateInstanceAs("disks", "disks-b", nil, "alice"); statusOf(err) != 409 {
		t.Errorf("single = %v", err)
	}
}

func TestInstanceDomainsAndRouters(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.SetDomainSource(&fakeDomains{list: []Domain{{Name: "b.example.net", State: DomainReady}, {Name: "a.example.net", State: "pending"}}})
	d := f.h.InstanceDomains()
	if len(d) != 3 || d[0].Name != "example.org" || !d[0].Main || !d[0].Assignable ||
		d[1].Name != "a.example.net" || d[1].Assignable || d[2].Name != "b.example.net" || !d[2].Assignable {
		t.Errorf("domains = %+v", d)
	}
	r, multi, legacy, ok := f.h.HostRouters("grafana")
	if !ok || !multi || legacy || len(r) != 1 || r[0].Router != "grafana" || r[0].Subdomain != "grafana" || r[0].Immutable {
		t.Errorf("routers = %+v %v %v %v", r, multi, legacy, ok)
	}
	if _, _, _, ok := f.h.HostRouters("nope"); ok {
		t.Error("unknown template")
	}
}
