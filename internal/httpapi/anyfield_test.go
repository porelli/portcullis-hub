package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAllowAnyFieldRoute: PUT …/allow-any-field is admins only, needs
// allow, is audited, re-evaluates the group, and shows on the overview;
// the refusal it fixes names both ways out.
func TestAllowAnyFieldRoute(t *testing.T) {
	e, _ := directoryToolEnv(t)
	e.ll.AddGroup("admin_secretapp")
	e.ll.AddUser("gus", "gus@example.org", "Gus", "")
	mustDo(t, e.hub, "root", "POST", "/api/directory/fields", `{"name":"dept","label":"Dept","kind":"text"}`, 200)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/users/gus/details", `{"attrs":{"dept":["Eng"]}}`, 200)
	convert := `{"rule":"dept = \"Eng\"","preview":{"matching":["gus"],"kept_as_exception":[],"joining":["gus"],"expiry_dropped":[]}}`
	body := mustDo(t, e.hub, "root", "POST", "/api/directory/groups/admin_secretapp/convert", convert, 409)
	if !strings.Contains(body, "make dept admin-only") || !strings.Contains(body, "Allow any profile field in this group's rule") {
		t.Errorf("refusal = %s", body)
	}
	mustDo(t, e.hub, "gus", "PUT", "/api/directory/groups/admin_secretapp/allow-any-field", `{"allow":true}`, 403)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/groups/admin_secretapp/allow-any-field", `{}`, 400)
	b := mustDo(t, e.hub, "root", "PUT", "/api/directory/groups/admin_secretapp/allow-any-field", `{"allow":true}`, 200)
	wantApplied(t, "allow-any-field", b)
	found := false
	for _, a := range readAudit(t, e.audit) {
		found = found || (a.Action == "group.allow_any_field" && a.Target == "admin_secretapp" && a.Detail == "allow=true" && a.Result == "ok")
	}
	if !found {
		t.Error("no group.allow_any_field entry")
	}
	var ov struct {
		Groups []struct {
			Name          string `json:"name"`
			AllowAnyField *bool  `json:"allow_any_field"`
		} `json:"groups"`
	}
	if err := json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/directory", "", 200)), &ov); err != nil {
		t.Fatal(err)
	}
	for _, g := range ov.Groups {
		if g.Name == "admin_secretapp" && (g.AllowAnyField == nil || !*g.AllowAnyField) {
			t.Errorf("overview admin_secretapp allow_any_field = %v", g.AllowAnyField)
		}
	}
	b = mustDo(t, e.hub, "root", "POST", "/api/directory/groups/admin_secretapp/convert", convert, 200)
	wantApplied(t, "convert", b)
	if m := e.ll.GroupMembers("admin_secretapp"); len(m) != 1 || m[0] != "gus" {
		t.Errorf("admin_secretapp = %v, want gus", m)
	}
}
