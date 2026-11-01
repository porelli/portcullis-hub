package lldap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
)

const svcPass = "s3rvice-Passw0rd-very-secret"

func writeCreds(t *testing.T, user, pass string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "username"), []byte(user+"\n"), 0600)
	os.WriteFile(filepath.Join(dir, "password"), []byte(pass+"\n"), 0600)
	return dir
}

func newClient(t *testing.T) (*lldap.Client, *lldaptest.Server) {
	t.Helper()
	f := lldaptest.New(t, "portcullis-hub", svcPass)
	return lldap.New(f.HTTP.URL, f.LDAPURL(), f.BaseDN, writeCreds(t, "portcullis-hub", svcPass)), f
}

func TestNotConfigured(t *testing.T) {
	c := lldap.New("http://127.0.0.1:1", "ldap://127.0.0.1:1", "dc=x", filepath.Join(t.TempDir(), "missing"))
	if err := c.Available(); !errors.Is(err, lldap.ErrNotConfigured) {
		t.Errorf("Available = %v", err)
	}
	if _, err := c.ListUsers(context.Background()); !errors.Is(err, lldap.ErrNotConfigured) {
		t.Errorf("ListUsers = %v", err)
	}
	empty := writeCreds(t, "portcullis-hub", "")
	if err := lldap.New("", "", "", empty).Available(); !errors.Is(err, lldap.ErrNotConfigured) {
		t.Errorf("empty password file accepted: %v", err)
	}
	bad := writeCreds(t, "uid=x,dc=evil", "pw")
	if err := lldap.New("", "", "", bad).Available(); !errors.Is(err, lldap.ErrNotConfigured) {
		t.Errorf("DN-ish username accepted: %v", err)
	}
}

func TestCRUDAndTokenReuse(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	if c.ServiceUser() != "portcullis-hub" {
		t.Errorf("ServiceUser = %q", c.ServiceUser())
	}
	if err := c.CreateUser(ctx, "alice", "alice@example.org", "Alice"); err != nil {
		t.Fatal(err)
	}
	gid, err := c.CreateGroup(ctx, "users_app")
	if err != nil || gid == 0 {
		t.Fatalf("CreateGroup = %d, %v", gid, err)
	}
	if err := c.AddUserToGroup(ctx, "alice", gid); err != nil {
		t.Fatal(err)
	}
	email, name := "a@example.org", "Alice A"
	if err := c.UpdateUser(ctx, "alice", &email, &name); err != nil {
		t.Fatal(err)
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var alice *lldap.User
	for i := range users {
		if users[i].ID == "alice" {
			alice = &users[i]
		}
	}
	if alice == nil || alice.Email != email || alice.DisplayName != name || len(alice.Groups) != 1 || alice.Groups[0].DisplayName != "users_app" {
		t.Fatalf("alice = %+v", alice)
	}
	groups, err := c.ListGroups(ctx)
	if err != nil || len(groups) != 4 {
		t.Fatalf("groups = %v, %v", groups, err)
	}
	if err := c.RemoveUserFromGroup(ctx, "alice", gid); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(ctx, gid); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, "alice"); err != nil || f.HasUser("alice") {
		t.Fatalf("delete: %v", err)
	}
	// GraphQL errors surface as GraphQLError.
	var ge *lldap.GraphQLError
	if err := c.DeleteGroup(ctx, 1); !errors.As(err, &ge) || !strings.Contains(err.Error(), "admin group") {
		t.Errorf("DeleteGroup(1) = %v", err)
	}
	if f.Logins != 1 {
		t.Errorf("logins = %d, want 1 (token reused)", f.Logins)
	}
}

func TestReauthOn401(t *testing.T) {
	c, f := newClient(t)
	f.ExpireTokens = true
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.ListUsers(ctx); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// First call logs in; each later 401 is answered via the refresh token.
	if f.Logins != 1 || f.Refreshes != 2 {
		t.Errorf("logins = %d, refreshes = %d", f.Logins, f.Refreshes)
	}
}

func TestWrongPasswordNoSecretInError(t *testing.T) {
	f := lldaptest.New(t, "portcullis-hub", svcPass)
	wrong := "wrong-but-secret-value"
	c := lldap.New(f.HTTP.URL, f.LDAPURL(), f.BaseDN, writeCreds(t, "portcullis-hub", wrong))
	_, err := c.ListUsers(context.Background())
	if err == nil || strings.Contains(err.Error(), wrong) {
		t.Errorf("err = %v", err)
	}
	if err := c.SetPassword(context.Background(), "admin", "NewPassword-123"); err == nil || strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), "NewPassword") {
		t.Errorf("SetPassword with bad bind = %v", err)
	}
}

func TestSetPassword(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	f.AddUser("bob", "bob@example.org", "Bob", "")
	if err := c.SetPassword(ctx, "bob", "a-long-new-password"); err != nil {
		t.Fatal(err)
	}
	if f.Password("bob") != "a-long-new-password" {
		t.Errorf("password not set")
	}
	f.FailPassword = 50
	var re *lldap.ResultError
	if err := c.SetPassword(ctx, "bob", "another-password"); !errors.As(err, &re) || re.Code != 50 || strings.Contains(err.Error(), "another-password") {
		t.Errorf("failure = %v", err)
	}
	if err := c.SetPassword(ctx, "nobody", "a-long-new-password"); err == nil {
		t.Error("unknown user accepted")
	}
	if err := c.SetPassword(ctx, "bob,ou=x", "a-long-new-password"); err == nil {
		t.Error("DN injection accepted")
	}
	// Large values exercise long-form BER lengths.
	long := strings.Repeat("p", 200)
	if err := c.SetPassword(ctx, "bob", long); err != nil || f.Password("bob") != long {
		t.Errorf("long password: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for _, u := range []string{"alice", "a", "bob.smith", "x_y-z9", strings.Repeat("a", 64)} {
		if !lldap.ValidUsername(u) {
			t.Errorf("rejected %q", u)
		}
	}
	for _, u := range []string{"", "Alice", "-x", ".x", "a b", "a,b", "a=b", "a+b", "é", strings.Repeat("a", 65), "a/b"} {
		if lldap.ValidUsername(u) {
			t.Errorf("accepted %q", u)
		}
	}
	for _, e := range []string{"a@example.org", "a.b+c@sub.example.org"} {
		if !lldap.ValidEmail(e) {
			t.Errorf("rejected %q", e)
		}
	}
	for _, e := range []string{"", "a", "a@b", "Alice <a@example.org>", "a@example.org,b@example.org", "a b@example.org"} {
		if lldap.ValidEmail(e) {
			t.Errorf("accepted %q", e)
		}
	}
	if lldap.ValidPassword("short") || lldap.ValidPassword("long-enough\x00pw") || !lldap.ValidPassword("long-enough-pw") {
		t.Error("password validation")
	}
	if lldap.ValidDisplayName("a\nb") || !lldap.ValidDisplayName("Ünïcode Name") {
		t.Error("display name validation")
	}
	if !lldap.ValidGroupName("users_app") || lldap.ValidGroupName("__x") || lldap.ValidGroupName("a b") {
		t.Error("group validation")
	}
}

func TestUserAttributesRoundTrip(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	f.AddUser("anna", "anna@example.org", "Anna", "")
	// Add custom attributes to the schema.
	if err := c.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := c.AddUserAttribute(ctx, "languages", true); err != nil {
		t.Fatal(err)
	}
	// Set attributes on anna.
	if err := c.SetUserAttributes(ctx, "anna", map[string][]string{"city": {"Milan"}, "languages": {"it", "en"}}, nil); err != nil {
		t.Fatal(err)
	}
	// ListUsers returns them.
	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var anna *lldap.User
	for i := range users {
		if users[i].ID == "anna" {
			anna = &users[i]
		}
	}
	if anna == nil {
		t.Fatal("anna not found")
	}
	if len(anna.Attributes) != 2 {
		t.Fatalf("attributes = %+v, want 2 entries", anna.Attributes)
	}
	if len(anna.Attributes["city"]) != 1 || anna.Attributes["city"][0] != "Milan" {
		t.Errorf("city = %v", anna.Attributes["city"])
	}
	if len(anna.Attributes["languages"]) != 2 || anna.Attributes["languages"][0] != "it" || anna.Attributes["languages"][1] != "en" {
		t.Errorf("languages = %v", anna.Attributes["languages"])
	}
	// Remove city.
	if err := c.SetUserAttributes(ctx, "anna", nil, []string{"city"}); err != nil {
		t.Fatal(err)
	}
	users, err = c.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range users {
		if users[i].ID == "anna" {
			anna = &users[i]
		}
	}
	if len(anna.Attributes) != 1 || anna.Attributes["city"] != nil {
		t.Errorf("after remove: attributes = %+v", anna.Attributes)
	}
	if len(anna.Attributes["languages"]) != 2 {
		t.Errorf("languages after remove = %v", anna.Attributes["languages"])
	}
}

func TestAddUserAttributeFlags(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	if err := c.AddUserAttribute(ctx, "department", false); err != nil {
		t.Fatal(err)
	}
	if err := c.AddUserAttribute(ctx, "tags", true); err != nil {
		t.Fatal(err)
	}
	// Check the fake recorded the correct flags.
	attrs, err := c.UserAttributes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var department, tags *lldap.Attribute
	for i := range attrs {
		switch attrs[i].Name {
		case "department":
			department = &attrs[i]
		case "tags":
			tags = &attrs[i]
		}
	}
	if department == nil || department.IsList {
		t.Errorf("department = %+v", department)
	}
	if tags == nil || !tags.IsList {
		t.Errorf("tags = %+v", tags)
	}
	// The fake should have recorded attributeType=STRING, isVisible=true, isEditable=false.
	if len(f.UserAttributeSchema) != 2 {
		t.Fatalf("schema = %+v", f.UserAttributeSchema)
	}
	for _, name := range []string{"department", "tags"} {
		s := f.UserAttributeSchema[name]
		if s.AttributeType != "STRING" || !s.IsVisible || s.IsEditable {
			t.Errorf("%s schema = %+v, want STRING/visible/not-editable", name, s)
		}
	}
}

func TestSetUserAttributesValidation(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	f.AddUser("bob", "bob@example.org", "Bob", "")
	// Unknown attribute: error and no value stored.
	err := c.SetUserAttributes(ctx, "bob", map[string][]string{"unknown_field": {"value"}}, nil)
	if err == nil {
		t.Fatal("setting unknown attribute succeeded")
	}
	var ge *lldap.GraphQLError
	if !errors.As(err, &ge) || !strings.Contains(err.Error(), "schema") {
		t.Errorf("error = %v, want GraphQLError mentioning schema", err)
	}
	// Verify no value was stored.
	users, _ := c.ListUsers(ctx)
	var bob *lldap.User
	for i := range users {
		if users[i].ID == "bob" {
			bob = &users[i]
		}
	}
	if bob == nil || len(bob.Attributes) != 0 {
		t.Errorf("bob.Attributes = %+v, want empty (unknown attr rejected)", bob.Attributes)
	}
	// Add a single-valued attribute to schema.
	if err := c.AddUserAttribute(ctx, "office", false); err != nil {
		t.Fatal(err)
	}
	// Multiple values for single-valued attribute: error.
	err = c.SetUserAttributes(ctx, "bob", map[string][]string{"office": {"NYC", "LON"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "not a list") {
		t.Errorf("multi-value for single attr = %v, want error about 'not a list'", err)
	}
	// Single value: accepted.
	if err := c.SetUserAttributes(ctx, "bob", map[string][]string{"office": {"NYC"}}, nil); err != nil {
		t.Errorf("single value for single attr failed: %v", err)
	}
}
