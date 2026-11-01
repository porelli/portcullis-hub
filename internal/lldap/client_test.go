package lldap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
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
	if err := c.SetPassword(context.Background(), "admin", "NewPassword-123"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), "NewPassword") {
		t.Errorf("SetPassword with bad bind = %v", err)
	}
	if f.Password("admin") != "adminpass" {
		t.Error("password changed after a failed bind")
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
	if err := c.SetPassword(ctx, "bob", "another-password"); !ldap.IsErrorWithCode(err, 50) || strings.Contains(err.Error(), "another-password") {
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

func TestSetUserAttributesAtomic(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()
	// Set up: user with city attribute.
	if err := c.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateUser(ctx, "carol", "carol@example.org", "Carol"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetUserAttributes(ctx, "carol", map[string][]string{"city": {"Milan"}}, nil); err != nil {
		t.Fatal(err)
	}
	// Verify city is set.
	users, _ := c.ListUsers(ctx)
	var carol *lldap.User
	for i := range users {
		if users[i].ID == "carol" {
			carol = &users[i]
		}
	}
	if carol == nil || len(carol.Attributes["city"]) != 1 || carol.Attributes["city"][0] != "Milan" {
		t.Fatalf("setup failed: carol.city = %v", carol.Attributes["city"])
	}
	// Attempt: valid remove (city) + invalid insert (bogus attribute).
	err := c.SetUserAttributes(ctx, "carol", map[string][]string{"bogus": {"value"}}, []string{"city"})
	if err == nil {
		t.Fatal("operation with invalid insert succeeded")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error = %v, want mention of schema", err)
	}
	// Verify atomicity: city should still be Milan (remove was NOT applied).
	users, _ = c.ListUsers(ctx)
	for i := range users {
		if users[i].ID == "carol" {
			carol = &users[i]
		}
	}
	if carol == nil || len(carol.Attributes["city"]) != 1 || carol.Attributes["city"][0] != "Milan" {
		t.Errorf("after failed op: carol.city = %v, want [Milan] (remove should not have applied)", carol.Attributes["city"])
	}
}

func TestUpdateUserEmailAtomicity(t *testing.T) {
	c, f := newClient(t)
	ctx := context.Background()
	// Add an attribute schema so we can test invalid inserts.
	if err := c.AddUserAttribute(ctx, "department", false); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateUser(ctx, "dave", "dave@example.org", "Dave"); err != nil {
		t.Fatal(err)
	}
	users, _ := c.ListUsers(ctx)
	var dave *lldap.User
	for i := range users {
		if users[i].ID == "dave" {
			dave = &users[i]
		}
	}
	originalEmail := dave.Email
	// Send raw GraphQL mutation combining email update + invalid attribute.
	// First, get a token for authentication.
	_, err := c.ListUsers(ctx) // This will authenticate and get a token
	if err != nil {
		t.Fatal(err)
	}
	// Now craft a raw request to test the fake's updateUser atomicity.
	payload := map[string]interface{}{
		"query": `mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }`,
		"variables": map[string]interface{}{
			"user": map[string]interface{}{
				"id":    "dave",
				"email": "dave.new@example.org",
				"insertAttributes": []map[string]interface{}{
					{"name": "invalid_attr", "value": []string{"x"}},
				},
			},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", f.HTTP.URL+"/api/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Get token from a login request.
	loginPayload, _ := json.Marshal(map[string]string{"username": "portcullis-hub", "password": svcPass})
	loginReq, _ := http.NewRequest("POST", f.HTTP.URL+"/auth/simple/login", bytes.NewReader(loginPayload))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, _ := http.DefaultClient.Do(loginReq)
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	var loginResult struct{ Token string }
	json.Unmarshal(loginBody, &loginResult)
	req.Header.Set("Authorization", "Bearer "+loginResult.Token)
	// Execute the mutation.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Check response indicates error about schema.
	if !strings.Contains(string(respBody), "schema") {
		t.Errorf("response = %s, want error about schema", string(respBody))
	}
	// Verify email was NOT changed in fake's internal state.
	if f.Users["dave"]["email"] != originalEmail {
		t.Errorf("after failed op: email = %s, want %s (email should not have changed)", f.Users["dave"]["email"], originalEmail)
	}
}

// TestSetPasswordSilentServer: an LDAP server that accepts the connection but
// never answers must not hang the Hub (Timeout and ctx both bound it).
func TestSetPasswordSilentServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // read nothing, answer nothing
		}
	}()
	f := lldaptest.New(t, "portcullis-hub", svcPass)
	c := lldap.New(f.HTTP.URL, "ldap://"+l.Addr().String(), f.BaseDN, writeCreds(t, "portcullis-hub", svcPass))
	c.Timeout = 300 * time.Millisecond
	start := time.Now()
	if err := c.SetPassword(context.Background(), "admin", "NewPassword-123"); err == nil || strings.Contains(err.Error(), "NewPassword") {
		t.Errorf("silent server (timeout) = %v", err)
	}
	c.Timeout = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := c.SetPassword(ctx, "admin", "NewPassword-123"); err == nil {
		t.Error("silent server (ctx) succeeded")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}

// TestGraphQLHTTPErrors: non-200 GraphQL responses become "HTTP <code>"
// without echoing the body, and oversized bodies are cut at maxResponse.
func TestGraphQLHTTPErrors(t *testing.T) {
	f := lldaptest.New(t, "portcullis-hub", svcPass)
	mode := "500"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/graphql" {
			f.HTTP.Config.Handler.ServeHTTP(w, r) // login on the fake
			return
		}
		if mode == "500" {
			http.Error(w, "boom secret-body", 500)
			return
		}
		w.Write([]byte(`{"data":{"groups":[],"pad":"`))
		w.Write(bytes.Repeat([]byte("x"), 17<<20))
		w.Write([]byte(`"}}`))
	}))
	defer srv.Close()
	c := lldap.New(srv.URL, f.LDAPURL(), f.BaseDN, writeCreds(t, "portcullis-hub", svcPass))
	if _, err := c.ListGroups(context.Background()); err == nil || err.Error() != "lldap graphql: HTTP 500" {
		t.Errorf("500 = %v", err)
	}
	mode = "huge"
	if _, err := c.ListGroups(context.Background()); err == nil || err.Error() != "lldap graphql: response too large" {
		t.Errorf("oversized response accepted or echoed: %.200v", err)
	}
}

// TestSetPasswordOneDeadline: a server that answers the bind late and then
// never answers the Password Modify must fail within ONE Timeout overall
// (not one per request), and the client still sends an Unbind.
func TestSetPasswordOneDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	unbound := make(chan bool, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		sawUnbind := false
		defer func() { unbound <- sawUnbind }()
		for {
			p, err := ber.ReadPacket(c)
			if err != nil || len(p.Children) < 2 {
				return
			}
			id := p.Children[0].Value
			switch p.Children[1].Tag {
			case ldap.ApplicationBindRequest:
				time.Sleep(700 * time.Millisecond)
				resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
				br := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "")
				br.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
				br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				resp.AppendChild(br)
				c.Write(resp.Bytes())
			case ldap.ApplicationUnbindRequest:
				sawUnbind = true
				return
			} // extended request: never answered
		}
	}()
	f := lldaptest.New(t, "portcullis-hub", svcPass)
	c := lldap.New(f.HTTP.URL, "ldap://"+l.Addr().String(), f.BaseDN, writeCreds(t, "portcullis-hub", svcPass))
	c.Timeout = time.Second
	start := time.Now()
	if err := c.SetPassword(context.Background(), "admin", "NewPassword-123"); err == nil || strings.Contains(err.Error(), "NewPassword") {
		t.Errorf("stalled password modify = %v", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("took %v, want about one Timeout (1s)", d)
	}
	select {
	case saw := <-unbound:
		if !saw {
			t.Error("no Unbind sent before close")
		}
	case <-time.After(5 * time.Second):
		t.Error("server never saw the connection end")
	}
}
