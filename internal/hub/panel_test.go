package hub

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
)

// panelManifest: header-auth with an access group; storage_quota is a
// per-person size (file, account_creation; the file restarts the app on
// membership changes), trash_days an instance int (env, restart),
// api_key an env secret.
const panelManifest = `name: Panel App
category: tools
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_panelapp
  admin_group: admin_panelapp
urls:
  - label: Web
    url: "https://{{HOST_PANELAPP}}"
files:
  - {name: quota, service: app, mount: /portcullis, on_membership_change: restart}
settings:
  options:
    - key: storage_quota
      label: Storage quota
      type: size
      scope: person
      default: 10GiB
      resolve: max
      applies: account_creation
      delivery: [{file: {name: quota}}]
    - key: trash_days
      label: Trash days
      type: int
      min: 1
      default: 30
      applies: restart
      delivery: [{env: PANELAPP_TRASH_DAYS}]
    - key: api_key
      label: API key
      type: secret
      applies: restart
      generate: {length: 32, charset: alphanumeric}
      delivery: [{env: PANELAPP_API_KEY}]
`

const panelCompose = `services:
  app:
    image: panelapp
    environment:
      TRASH_DAYS: ${PANELAPP_TRASH_DAYS}
      API_KEY: ${PANELAPP_API_KEY}
    labels:
      traefik.enable: "true"
      traefik.http.routers.panelapp.rule: Host(` + "`${PORTCULLIS_HOST_PANELAPP:-panelapp.portcullis.local}`" + `)
      traefik.http.routers.panelapp.entrypoints: websecure
      traefik.http.routers.panelapp.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.services.panelapp.loadbalancer.server.port: "8080"
`

// panelFixture: alice, bob, carol in users_panelapp; office_milan holds
// alice, bob and frank (frank has no access); it_staff holds bob. The
// saved storage_quota: default 10 GiB, office_milan 1 TiB.
func panelFixture(t *testing.T) (*fixture, *fakeAudit, *fakePeople) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"panelapp": {panelManifest, panelCompose}})
	if f.h.Template("panelapp") == nil {
		t.Fatalf("panelapp fixture not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	people := newFakePeople("erin", "frank")
	people.addGroup("users_panelapp", "alice", "bob", "carol")
	people.addGroup("admin_panelapp")
	people.addGroup("office_milan", "alice", "bob", "frank")
	people.addGroup("it_staff", "bob")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_panelapp": true, "admin_panelapp": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	if err := f.h.save("panelapp", SettingsUpdate{Person: map[string]PersonChange{
		"storage_quota": {Default: raw("10GiB"), Rows: rows("office_milan", "1TiB")},
	}}); err != nil {
		t.Fatal(err)
	}
	return f, audit, people
}

func personPreview(p OptionPreview, user string) (PersonPreview, bool) {
	for _, x := range p.People {
		if x.User == user {
			return x, true
		}
	}
	return PersonPreview{}, false
}

func TestPreviewOnDraft(t *testing.T) {
	f, _, people := panelFixture(t)
	before := storedSettings(f, "panelapp")
	calls := people.calls
	draft := SettingsUpdate{Person: map[string]PersonChange{
		"storage_quota": {Default: raw("10GiB"), Rows: rows("office_milan", "1TiB", "it_staff", "2TiB")},
	}}
	p, err := f.h.PreviewSettings(context.Background(), "panelapp", draft)
	if err != nil {
		t.Fatal(err)
	}
	if people.calls != calls+1 {
		t.Errorf("preview made %d Membership calls, want 1", people.calls-calls)
	}
	op, ok := p.Options["storage_quota"]
	if !ok {
		t.Fatalf("preview options = %+v", p.Options)
	}
	var users []string
	for _, x := range op.People {
		users = append(users, x.User)
	}
	if strings.Join(users, ",") != "alice,bob,carol" {
		t.Errorf("people = %v, want the population sorted", users)
	}
	bob, _ := personPreview(op, "bob")
	if bob.Display != "2 TiB" || bob.Reason.Group != "it_staff" {
		t.Errorf("bob = %+v", bob)
	}
	lost := false
	for _, c := range bob.Reason.Others {
		lost = lost || c.Group == "office_milan"
	}
	if !lost {
		t.Errorf("bob's others = %+v, want office_milan", bob.Reason.Others)
	}
	if alice, _ := personPreview(op, "alice"); alice.Display != "1 TiB" || alice.Reason.Group != "office_milan" {
		t.Errorf("alice = %+v", alice)
	}
	if carol, _ := personPreview(op, "carol"); carol.Display != "10 GiB" || carol.Reason.Source != settings.ReasonDefault {
		t.Errorf("carol = %+v", carol)
	}
	if op.Changes != 1 {
		t.Errorf("changes = %d, want 1 (bob)", op.Changes)
	}
	if op.NoAccess["office_milan"] != 1 || op.NoAccess["it_staff"] != 0 {
		t.Errorf("no_access = %v, want office_milan 1 (frank)", op.NoAccess)
	}
	if after := storedSettings(f, "panelapp"); !reflect.DeepEqual(before, after) {
		t.Errorf("preview stored something:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestPreviewEffectText(t *testing.T) {
	f, _, _ := panelFixture(t)
	p, err := f.h.PreviewSettings(context.Background(), "panelapp", SettingsUpdate{Person: map[string]PersonChange{
		"storage_quota": {Default: raw("20GiB"), Rows: rows("office_milan", "1TiB")},
	}})
	if err != nil || p.Effect != settings.EffectNone {
		t.Fatalf("storage_quota only: %+v, %v; want effect none", p, err)
	}
	p, err = f.h.PreviewSettings(context.Background(), "panelapp", SettingsUpdate{Values: vals("trash_days", 7)})
	if err != nil || p.Effect != settings.EffectRestart {
		t.Fatalf("trash_days: %+v, %v; want effect restart", p, err)
	}
	if v := storedSettings(f, "panelapp").Values["trash_days"]; v != nil {
		t.Errorf("preview stored trash_days = %v", v)
	}
	// A refused draft is refused like the save, naming the option.
	if _, err := f.h.PreviewSettings(context.Background(), "panelapp", SettingsUpdate{Values: vals("trash_days", 0)}); statusOf(err) != 400 || !strings.Contains(err.Error(), "trash_days") {
		t.Errorf("bad draft = %v", err)
	}
}

// An unresolved person value is shown as such, never as the default.
func TestPreviewUnresolvedText(t *testing.T) {
	if got := previewDisplay(nil, nil, settings.Resolved{Reason: settings.Reason{Source: settings.ReasonFailClosed}}); got != UnresolvedText {
		t.Errorf("display = %q", got)
	}
	if UnresolvedText != "unresolved: the app's own default applies" {
		t.Errorf("text = %q", UnresolvedText)
	}
}

func TestPrivilegedGroupChoices(t *testing.T) {
	f, _, people := privFixture(t)
	people.set(func(p *fakePeople) {
		p.privilege["office_milan"] = "its rule uses fields delegates can edit: office_location"
	})
	p, err := f.h.SettingsPanel(context.Background(), "privapp")
	if err != nil {
		t.Fatal(err)
	}
	var role, tier *OptionView
	for i := range p.Options {
		switch p.Options[i].Key {
		case "role":
			role = &p.Options[i]
		case "tier":
			tier = &p.Options[i]
		}
	}
	if role == nil || tier == nil {
		t.Fatalf("options = %+v", p.Options)
	}
	if len(tier.GroupChoices) != 0 {
		t.Errorf("a non-privileged option has group choices: %+v", tier.GroupChoices)
	}
	choices := map[string]PrivilegedGroupChoice{}
	for _, c := range role.GroupChoices {
		choices[c.Name] = c
	}
	if c := choices["office_milan"]; !c.Disabled || c.Reason != "its rule uses fields delegates can edit: office_location" {
		t.Errorf("office_milan = %+v", c)
	}
	if c, ok := choices["admin_privapp"]; !ok || c.Disabled {
		t.Errorf("admin_privapp = %+v (%v)", c, ok)
	}
}

func TestPanelContents(t *testing.T) {
	f, _, people := panelFixture(t)
	if _, err := f.h.SaveSettings("panelapp", SettingsUpdate{Values: vals("trash_days", 14), Secrets: map[string]SecretChange{"api_key": {Value: strp("s3cr3t-panel-value")}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	p, err := f.h.SettingsPanel(context.Background(), "panelapp")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "s3cr3t-panel-value") {
		t.Fatalf("panel carries the secret: %s", b)
	}
	if !p.Secrets["api_key"].Set {
		t.Errorf("secrets = %+v", p.Secrets)
	}
	if p.Instance["trash_days"] != int64(14) {
		t.Errorf("instance = %+v", p.Instance)
	}
	if _, ok := p.Instance["api_key"]; ok {
		t.Errorf("instance values carry the secret option")
	}
	if p.Population.Count != 3 || p.Population.Why != "" {
		t.Errorf("population = %+v", p.Population)
	}
	rs := p.Person["storage_quota"].Rows
	if len(rs) != 1 || rs[0].Group != "office_milan" || rs[0].GroupID != people.id("office_milan") {
		t.Errorf("person rows = %+v, want office_milan with its stored id", rs)
	}
	if p.Entries == nil || len(p.Entries) != 0 {
		t.Errorf("entries = %+v, want empty (Task 15A)", p.Entries)
	}
	var quota *OptionView
	for i := range p.Options {
		if p.Options[i].Key == "storage_quota" {
			quota = &p.Options[i]
		}
	}
	if quota == nil || quota.DefaultDisplay != "10 GiB" || quota.Effect != settings.EffectNone {
		t.Fatalf("storage_quota view = %+v", quota)
	}
	w := strings.Join(quota.Warnings, "|")
	if !strings.Contains(w, "existing accounts keep their value") || !strings.Contains(w, "people joining or leaving restarts Panel App") {
		t.Errorf("warnings = %q", w)
	}
	if _, ok := b2m(t, b)["values"]; ok {
		t.Errorf("the panel still has the old flat values")
	}
}

func b2m(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The panel sends each row's stored group id back; a save carrying an id
// the stored row doesn't have (the row was purged, or its group
// re-created) is refused 409; a row without an id is a new row.
func TestSaveGroupIDRoundTrip(t *testing.T) {
	f, _, people := panelFixture(t)
	milan := people.id("office_milan")
	withID := func(id int, extra ...GroupValueInput) SettingsUpdate {
		rs := append([]GroupValueInput{{Group: "office_milan", Value: raw("1TiB"), GroupID: id}}, extra...)
		return SettingsUpdate{Person: map[string]PersonChange{"storage_quota": {Default: raw("10GiB"), Rows: rs}}}
	}
	if err := f.h.save("panelapp", withID(milan, GroupValueInput{Group: "it_staff", Value: raw("2TiB")})); err != nil {
		t.Fatalf("resend with the stored id + a new row: %v", err)
	}
	if err := f.h.save("panelapp", withID(milan+1000)); statusOf(err) != 409 || !strings.Contains(err.Error(), "re-created since its row was saved") {
		t.Errorf("another id = %v, want 409", err)
	}
	// Purged (the group deleted and re-created): the stale panel resends
	// the old id.
	f.h.PurgeGroupSettings(context.Background(), directory.Human("root"), "office_milan", milan)
	people.deleteGroup("office_milan")
	people.addGroup("office_milan", "alice")
	if err := f.h.save("panelapp", withID(milan)); statusOf(err) != 409 {
		t.Errorf("resend after purge = %v, want 409", err)
	}
	if _, err := f.h.PreviewSettings(context.Background(), "panelapp", withID(milan)); statusOf(err) != 409 {
		t.Errorf("preview of a resend after purge = %v, want 409", err)
	}
	if err := f.h.save("panelapp", withID(0)); err != nil {
		t.Errorf("a new row (no id) = %v", err)
	}
	if rs := storedSettings(f, "panelapp").Person["storage_quota"].Rows; len(rs) != 1 || rs[0].GroupID != people.id("office_milan") {
		t.Errorf("rows = %+v", rs)
	}
}

// Placeholder rows are shown as the instance's group names and stay
// placeholders when the panel sends them back.
func TestPanelPlaceholderRoundTrip(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.EnableAs("privapp", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	p, err := f.h.SettingsPanel(context.Background(), "privapp")
	if err != nil {
		t.Fatal(err)
	}
	rs := p.Person["role"].Rows
	if len(rs) != 1 || rs[0].Group != "admin_privapp" || rs[0].GroupID != people.id("admin_privapp") {
		t.Fatalf("role rows = %+v", rs)
	}
	in := []GroupValueInput{{Group: rs[0].Group, GroupID: rs[0].GroupID, Value: raw(rs[0].Value)}}
	if err := f.h.save("privapp", SettingsUpdate{Person: map[string]PersonChange{"role": {Default: raw("user"), Rows: in}}}); err != nil {
		t.Fatal(err)
	}
	if got := storedSettings(f, "privapp").Person["role"].Rows; len(got) != 1 || got[0].Group != "{{ADMIN_GROUP}}" {
		t.Errorf("stored rows = %+v, want the placeholder kept", got)
	}
}

func TestRetryAudited(t *testing.T) {
	f, audit, _ := panelFixture(t)
	if err := f.h.Enable("panelapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	rep, err := f.h.RetryDeliveries(context.Background(), "panelapp", directory.Human("root"))
	if err != nil || rep == nil || rep.Instance != "panelapp" {
		t.Fatalf("retry = %+v, %v", rep, err)
	}
	es := auditsOf(audit, "settings.retry")
	if len(es) != 1 || es[0].Actor != "root" || es[0].Target != "panelapp" || es[0].Result != "ok" {
		t.Errorf("audit = %+v", es)
	}
	if _, err := f.h.RetryDeliveries(context.Background(), "nope", directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("unknown instance = %v", err)
	}
}

// The env rows of an option's variables: source option, Hub-set (an
// override is refused naming the setting); a secret option's is masked.
func TestEnvRowsOptionsHubSet(t *testing.T) {
	f, _, _ := panelFixture(t)
	if _, err := f.h.SaveSettings("panelapp", SettingsUpdate{Values: vals("trash_days", 14), Secrets: map[string]SecretChange{"api_key": {Value: strp("s3cr3t-panel-value")}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	rows, err := f.h.EnvRows("panelapp")
	if err != nil {
		t.Fatal(err)
	}
	if r := envRowOf(rows, "PANELAPP_TRASH_DAYS"); r == nil || r.Source != EnvSourceOption || !r.HubSet || r.Default != "14" {
		t.Errorf("PANELAPP_TRASH_DAYS = %+v", r)
	}
	if r := envRowOf(rows, "PANELAPP_API_KEY"); r == nil || !r.Secret || r.Default != "[set]" {
		t.Errorf("PANELAPP_API_KEY = %+v", r)
	}
	if err := envOverrideErr(f.h, "panelapp", "PANELAPP_TRASH_DAYS", "3"); statusOf(err) != 400 || !strings.Contains(err.Error(), "trash_days") {
		t.Errorf("an owned variable = %v, want 400", err)
	}
}

// A draft that switches to the app's own login reaches nobody: the
// preview's population is empty with the native-sign-in reason, and
// switching back to Portcullis sign-in brings the people back.
func TestPreviewNativeSignInDraft(t *testing.T) {
	m := mustRead(t, filepath.Join("testdata", "settings", "nativeapp", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "nativeapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{nativeID: {string(m), string(c)}})
	if f.h.Template(nativeID) == nil {
		t.Fatalf("nativeapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople()
	people.addGroup("users_nativeapp", "alice", "bob")
	f.h.SetPeople(people)

	p, err := f.h.PreviewSettings(context.Background(), nativeID, SettingsUpdate{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Population.Count != 2 || p.Population.Why != "" || len(p.Options["seats"].People) != 2 {
		t.Fatalf("gateway: population %+v, seats %+v", p.Population, p.Options["seats"])
	}
	p, err = f.h.PreviewSettings(context.Background(), nativeID, SettingsUpdate{SignIn: strp(SignInNative)})
	if err != nil {
		t.Fatal(err)
	}
	if p.Population.Count != 0 || p.Population.Why != WhyNativeSignIn || len(p.Options["seats"].People) != 0 {
		t.Errorf("native draft: population %+v, seats %+v", p.Population, p.Options["seats"])
	}
	if f.h.SignInMode(nativeID) != SignInGateway {
		t.Errorf("the preview stored the sign-in mode")
	}
	// Stored native, draft back to gateway: the population is back.
	if err := f.h.save(nativeID, SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	p, err = f.h.PreviewSettings(context.Background(), nativeID, SettingsUpdate{SignIn: strp(SignInGateway)})
	if err != nil {
		t.Fatal(err)
	}
	if p.Population.Count != 2 || len(p.Options["seats"].People) != 2 {
		t.Errorf("gateway draft over a stored native: population %+v", p.Population)
	}
	panel, err := f.h.SettingsPanel(context.Background(), nativeID)
	if err != nil {
		t.Fatal(err)
	}
	if panel.Population.Why != WhyNativeSignIn {
		t.Errorf("stored native: panel population %+v", panel.Population)
	}
}

// The panel names the app, says whether it runs, and lists the
// directory's groups for the row pickers.
func TestPanelNameEnabledGroups(t *testing.T) {
	f, _, _ := panelFixture(t)
	p, err := f.h.SettingsPanel(context.Background(), "panelapp")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Panel App" || p.Enabled {
		t.Errorf("name %q enabled %v", p.Name, p.Enabled)
	}
	if got := strings.Join(p.DirectoryGroups, ","); got != "admin_panelapp,it_staff,office_milan,users_panelapp" {
		t.Errorf("directory groups = %s", got)
	}
	if err := f.h.Enable("panelapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if p, err = f.h.SettingsPanel(context.Background(), "panelapp"); err != nil || !p.Enabled {
		t.Errorf("after enable: %v %v", p.Enabled, err)
	}
	b, _ := json.Marshal(p)
	for _, k := range []string{`"name":"Panel App"`, `"enabled":true`, `"directory_groups":[`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("panel JSON lacks %s", k)
		}
	}
}
