package directory_test

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// TestFieldLLDAPNameMapping: a custom field's LLDAP attribute is the field
// name with '_' → '-' (LLDAP v0.6.3 refuses '_'); the mapping round-trips,
// no field name contains '-', and LLDAP attributes with '_' are no field.
func TestFieldLLDAPNameMapping(t *testing.T) {
	for _, f := range []string{"cost_center", "a1_b2", "department", "x", "abcdefghij_abcdefghij_abcdefghi"} {
		if !directory.ValidFieldName(f) {
			t.Fatalf("%q should be a valid field name", f)
		}
		a := lldap.FieldAttrName(f)
		if strings.Contains(a, "_") {
			t.Errorf("LLDAP name of %q = %q, contains '_'", f, a)
		}
		back, ok := lldap.FieldFromAttrName(a)
		if !ok || back != f {
			t.Errorf("FieldFromAttrName(%q) = %q, %v; want %q", a, back, ok, f)
		}
	}
	if got := lldap.FieldAttrName("cost_center"); got != "cost-center" {
		t.Errorf("FieldAttrName(cost_center) = %q, want cost-center", got)
	}
	for _, f := range []string{"a-b", "cost-center", "-a", "a-"} {
		if directory.ValidFieldName(f) {
			t.Errorf("%q: a field name must never contain '-' (the mapping would not be bijective)", f)
		}
	}
	for _, a := range []string{"cost_center", "a_b-c", "_"} {
		if f, ok := lldap.FieldFromAttrName(a); ok {
			t.Errorf("FieldFromAttrName(%q) = %q, ok; an attribute with '_' is no field", a, f)
		}
	}

	// End to end against the fake (which refuses '_' like LLDAP): the
	// field is created as cost-center, written and read back as
	// cost_center, evaluated by a rule; an LLDAP attribute cost_center
	// (impossible in a real LLDAP) is ignored.
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "cost_center", Label: "Cost center", Kind: directory.FieldKindText, ShareWithApps: true}); err != nil {
		t.Fatalf("CreateField(cost_center): %v", err)
	}
	if _, ok := e.ll.UserAttributeSchema["cost-center"]; !ok {
		t.Fatalf("LLDAP schema lacks cost-center: %v", e.ll.UserAttributeSchema)
	}
	if _, ok := e.ll.UserAttributeSchema["cost_center"]; ok {
		t.Fatal("LLDAP schema has cost_center")
	}
	if err := e.svc.SetDetails(ctx, asRoot, "alice", map[string][]string{"cost_center": {"CC-42"}}); err != nil {
		t.Fatalf("SetDetails: %v", err)
	}
	if got := e.ll.UserAttributeValues["alice"]["cost-center"]; !reflect.DeepEqual(got, []string{"CC-42"}) {
		t.Fatalf("LLDAP alice cost-center = %v", got)
	}
	// A stray '_' attribute (written straight into the fake) is no field.
	e.ll.UserAttributeValues["alice"]["cost_center"] = []string{"STRAY"}
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range ov.Users {
		if u.Username == "alice" {
			found = true
			if !reflect.DeepEqual(u.Attrs, map[string][]string{"cost_center": {"CC-42"}}) {
				t.Errorf("overview alice attrs = %v, want cost_center CC-42 only", u.Attrs)
			}
		}
	}
	if !found {
		t.Fatal("alice not in overview")
	}
	rule, err := rules.Parse(`cost_center = "CC-42"`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &directory.Config{Groups: map[string]*directory.GroupConfig{"cc42": {Rule: rule}}}
	cfg.Fields = []directory.Field{{Name: "cost_center", Label: "Cost center", Kind: directory.FieldKindText}}
	want, err := e.svc.DesiredFromLLDAP(ctx, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !want["cc42"]["alice"] {
		t.Errorf("rule cost_center = CC-42 does not match alice: %v", want["cc42"])
	}
	// Delete removes the mapped attribute.
	if err := e.svc.DeleteField(ctx, asRoot, "cost_center", "cost_center"); err != nil {
		t.Fatalf("DeleteField: %v", err)
	}
	if _, ok := e.ll.UserAttributeSchema["cost-center"]; ok {
		t.Error("cost-center still in LLDAP after DeleteField")
	}
}

// TestFieldPsPrefixReserved: a field ps_<x> would be LLDAP attribute
// ps-<x>, the Hub's per-person setting attribute namespace.
func TestFieldPsPrefixReserved(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "ps_0123456789ab", Label: "X", Kind: directory.FieldKindText})
	if status(err) != 409 {
		t.Fatalf("CreateField(ps_0123456789ab) = %v, want 409", err)
	}
	if len(e.ll.UserAttributeSchema) != 0 {
		t.Errorf("LLDAP schema changed: %v", e.ll.UserAttributeSchema)
	}
}
