package settings

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

const GiB = int64(1) << 30

func TestDefaultIsFallbackOnly(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:    templates.TypeSize,
		Resolve: templates.ResolveMax,
	}
	config := PersonConfig{
		Default: int64(500 * GiB),
		Rule:    o.Resolve,
		Rows: []Row{
			{Group: "office_milan", GroupID: 5, Value: int64(10 * GiB)},
		},
	}

	// Alice is in office_milan → she gets the row's value
	alice := Person{User: "alice", Groups: map[string]int{"office_milan": 5}}
	res := r.Resolve(o, config, alice)
	if res.Value != int64(10*GiB) {
		t.Errorf("alice: want 10 GiB, got %v", res.Value)
	}
	if res.Reason.Source != ReasonGroup {
		t.Errorf("alice: want source %s, got %s", ReasonGroup, res.Reason.Source)
	}
	if res.Reason.Group != "office_milan" {
		t.Errorf("alice: want group office_milan, got %s", res.Reason.Group)
	}

	// Carol is in no row group → she gets the default
	carol := Person{User: "carol", Groups: map[string]int{}}
	res = r.Resolve(o, config, carol)
	if res.Value != int64(500*GiB) {
		t.Errorf("carol: want 500 GiB, got %v", res.Value)
	}
	if res.Reason.Source != ReasonDefault {
		t.Errorf("carol: want source %s, got %s", ReasonDefault, res.Reason.Source)
	}
}

func TestMaxMinWithUnlimited(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:           templates.TypeSize,
		AllowUnlimited: true,
	}

	rows := []Row{
		{Group: "office_milan", GroupID: 7, Value: int64(10 * GiB)},
		{Group: "it_staff", GroupID: 9, Value: Unlimited{}},
	}

	bob := Person{
		User:   "bob",
		Groups: map[string]int{"office_milan": 7, "it_staff": 9},
	}

	// Max: unlimited wins
	o.Resolve = templates.ResolveMax
	config := PersonConfig{Default: int64(1 * GiB), Rule: o.Resolve, Rows: rows}
	res := r.Resolve(o, config, bob)
	if _, ok := res.Value.(Unlimited); !ok {
		t.Errorf("max: want unlimited, got %v (%T)", res.Value, res.Value)
	}
	if res.Reason.Group != "it_staff" {
		t.Errorf("max: want group it_staff, got %s", res.Reason.Group)
	}
	if len(res.Reason.Others) != 1 || res.Reason.Others[0].Group != "office_milan" {
		t.Errorf("max: want Others=[{office_milan, 10GiB}], got %v", res.Reason.Others)
	}

	// Min: 10 GiB wins, Others includes unlimited
	o.Resolve = templates.ResolveMin
	config.Rule = o.Resolve
	res = r.Resolve(o, config, bob)
	if res.Value != int64(10*GiB) {
		t.Errorf("min: want 10 GiB, got %v", res.Value)
	}
	if res.Reason.Group != "office_milan" {
		t.Errorf("min: want group office_milan, got %s", res.Reason.Group)
	}
	if len(res.Reason.Others) != 1 || res.Reason.Others[0].Group != "it_staff" {
		t.Errorf("min: want Others=[{it_staff, unlimited}], got %v", res.Reason.Others)
	}

	// Tie case: two equal values, earlier row wins
	o.Resolve = templates.ResolveMax
	tieRows := []Row{
		{Group: "office_milan", GroupID: 7, Value: int64(10 * GiB)},
		{Group: "office_paris", GroupID: 8, Value: int64(10 * GiB)},
	}
	config.Rows = tieRows
	alice := Person{
		User:   "alice",
		Groups: map[string]int{"office_milan": 7, "office_paris": 8},
	}
	res = r.Resolve(o, config, alice)
	if res.Value != int64(10*GiB) {
		t.Errorf("tie: want 10 GiB, got %v", res.Value)
	}
	if res.Reason.Group != "office_milan" {
		t.Errorf("tie: want group office_milan (earlier), got %s", res.Reason.Group)
	}
	if len(res.Reason.Others) != 1 {
		t.Errorf("tie: want 1 Other, got %d", len(res.Reason.Others))
	}
}

func TestPriorityRowOrder(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:    templates.TypeString,
		Resolve: templates.ResolvePriority,
	}

	// Bob is in both groups
	bob := Person{
		User:   "bob",
		Groups: map[string]int{"it_staff": 9, "office_milan": 7},
	}

	// First order: it_staff wins
	config := PersonConfig{
		Default: "default",
		Rule:    o.Resolve,
		Rows: []Row{
			{Group: "it_staff", GroupID: 9, Value: "it_value"},
			{Group: "office_milan", GroupID: 7, Value: "milan_value"},
		},
	}
	res := r.Resolve(o, config, bob)
	if res.Value != "it_value" {
		t.Errorf("first order: want it_value, got %v", res.Value)
	}
	if res.Reason.Group != "it_staff" {
		t.Errorf("first order: want group it_staff, got %s", res.Reason.Group)
	}

	// Reordered: office_milan wins
	config.Rows = []Row{
		{Group: "office_milan", GroupID: 7, Value: "milan_value"},
		{Group: "it_staff", GroupID: 9, Value: "it_value"},
	}
	res = r.Resolve(o, config, bob)
	if res.Value != "milan_value" {
		t.Errorf("reordered: want milan_value, got %v", res.Value)
	}
	if res.Reason.Group != "office_milan" {
		t.Errorf("reordered: want group office_milan, got %s", res.Reason.Group)
	}
}

func TestUnionIntersection(t *testing.T) {
	r := NewRegistry()

	// Test with multi_enum: real Choices, assert canonical order on shuffled union
	o := &templates.Option{
		Type:    templates.TypeMultiEnum,
		Resolve: templates.ResolveUnion,
		Choices: []templates.EnumOption{
			{Value: "a", Label: "A"},
			{Value: "b", Label: "B"},
			{Value: "c", Label: "C"},
			{Value: "d", Label: "D"},
		},
	}

	// Rows with shuffled order: c,b in first, a,c in second
	rows := []Row{
		{Group: "it_staff", GroupID: 9, Value: []any{"c", "b"}},
		{Group: "office_milan", GroupID: 7, Value: []any{"a", "c"}},
		{Group: "office_paris", GroupID: 8, Value: []any{"d"}}, // bob isn't in this
	}
	bob := Person{
		User:   "bob",
		Groups: map[string]int{"it_staff": 9, "office_milan": 7},
	}

	config := PersonConfig{Default: []any{}, Rule: o.Resolve, Rows: rows}
	res := r.Resolve(o, config, bob)
	union := res.Value.([]any)
	// Canonical order is option order: a, b, c (not d since bob isn't in office_paris)
	if len(union) != 3 || union[0] != "a" || union[1] != "b" || union[2] != "c" {
		t.Errorf("union: want canonical order [a b c], got %v", union)
	}
	if res.Reason.Source != ReasonCombined {
		t.Errorf("union: want source %s, got %s", ReasonCombined, res.Reason.Source)
	}
	if len(res.Reason.Groups) != 2 {
		t.Errorf("union: want 2 groups, got %d: %v", len(res.Reason.Groups), res.Reason.Groups)
	}
	// Groups should be sorted
	if len(res.Reason.Groups) == 2 && (res.Reason.Groups[0] != "it_staff" || res.Reason.Groups[1] != "office_milan") {
		t.Errorf("union: want sorted groups [it_staff office_milan], got %v", res.Reason.Groups)
	}

	// Intersection on multi_enum
	o.Resolve = templates.ResolveIntersection
	config.Rule = o.Resolve
	res = r.Resolve(o, config, bob)
	inter := res.Value.([]any)
	if len(inter) != 1 || inter[0] != "c" {
		t.Errorf("intersection: want [c], got %v", inter)
	}
	if res.Reason.Source != ReasonCombined {
		t.Errorf("intersection: want source %s, got %s", ReasonCombined, res.Reason.Source)
	}

	// Test with groups type: assert sorted value + exact Reason.Groups, covers intersection
	o2 := &templates.Option{
		Type:    templates.TypeGroups,
		Resolve: templates.ResolveUnion,
	}
	rowsGroups := []Row{
		{Group: "it_staff", GroupID: 9, Value: []any{"group_c", "group_a"}}, // shuffled
		{Group: "office_milan", GroupID: 7, Value: []any{"group_b", "group_a"}},
	}
	config2 := PersonConfig{Default: []any{}, Rule: o2.Resolve, Rows: rowsGroups}
	res = r.Resolve(o2, config2, bob)
	unionGroups := res.Value.([]any)
	// groups type canonicalizes: sorted
	if len(unionGroups) != 3 || unionGroups[0] != "group_a" || unionGroups[1] != "group_b" || unionGroups[2] != "group_c" {
		t.Errorf("groups union: want sorted [group_a group_b group_c], got %v", unionGroups)
	}
	if res.Reason.Source != ReasonCombined {
		t.Errorf("groups union: want source %s, got %s", ReasonCombined, res.Reason.Source)
	}
	// Exact Reason.Groups check
	if len(res.Reason.Groups) != 2 || res.Reason.Groups[0] != "it_staff" || res.Reason.Groups[1] != "office_milan" {
		t.Errorf("groups union: want Reason.Groups=[it_staff office_milan], got %v", res.Reason.Groups)
	}

	// groups intersection
	o2.Resolve = templates.ResolveIntersection
	config2.Rule = o2.Resolve
	res = r.Resolve(o2, config2, bob)
	interGroups := res.Value.([]any)
	if len(interGroups) != 1 || interGroups[0] != "group_a" {
		t.Errorf("groups intersection: want [group_a], got %v", interGroups)
	}

	// Intersection with a non-list match → []any{}
	o3 := &templates.Option{
		Type:    templates.TypeMultiEnum,
		Resolve: templates.ResolveIntersection,
		Choices: []templates.EnumOption{
			{Value: "a", Label: "A"},
			{Value: "b", Label: "B"},
		},
	}
	rowsWithNonList := []Row{
		{Group: "it_staff", GroupID: 9, Value: []any{"a", "b"}},
		{Group: "office_milan", GroupID: 7, Value: "not_a_list"}, // non-list
	}
	config3 := PersonConfig{Default: []any{}, Rule: o3.Resolve, Rows: rowsWithNonList}
	res = r.Resolve(o3, config3, bob)
	interEmpty := res.Value.([]any)
	if len(interEmpty) != 0 {
		t.Errorf("intersection with non-list: want [], got %v", interEmpty)
	}

	// First list with duplicate items doesn't pass an item missing from another row
	o4 := &templates.Option{
		Type:    templates.TypeMultiEnum,
		Resolve: templates.ResolveIntersection,
		Choices: []templates.EnumOption{
			{Value: "a", Label: "A"},
			{Value: "b", Label: "B"},
			{Value: "c", Label: "C"},
		},
	}
	rowsWithDupes := []Row{
		{Group: "it_staff", GroupID: 9, Value: []any{"a", "a", "b"}}, // duplicate "a"
		{Group: "office_milan", GroupID: 7, Value: []any{"b", "c"}},  // no "a"
	}
	config4 := PersonConfig{Default: []any{}, Rule: o4.Resolve, Rows: rowsWithDupes}
	res = r.Resolve(o4, config4, bob)
	interNoDupes := res.Value.([]any)
	// Only "b" is in both sets (duplicate "a" doesn't count twice)
	if len(interNoDupes) != 1 || interNoDupes[0] != "b" {
		t.Errorf("intersection with dupes: want [b], got %v", interNoDupes)
	}
}

func TestAnyAll(t *testing.T) {
	r := NewRegistry()

	rows := []Row{
		{Group: "it_staff", GroupID: 9, Value: true},
		{Group: "office_milan", GroupID: 7, Value: false},
	}
	bob := Person{
		User:   "bob",
		Groups: map[string]int{"it_staff": 9, "office_milan": 7},
	}

	// Any
	o := &templates.Option{
		Type:    templates.TypeBool,
		Resolve: templates.ResolveAny,
	}
	config := PersonConfig{Default: false, Rule: o.Resolve, Rows: rows}
	res := r.Resolve(o, config, bob)
	if res.Value != true {
		t.Errorf("any: want true, got %v", res.Value)
	}
	if res.Reason.Source != ReasonCombined {
		t.Errorf("any: want source %s, got %s", ReasonCombined, res.Reason.Source)
	}

	// All
	o.Resolve = templates.ResolveAll
	config.Rule = o.Resolve
	res = r.Resolve(o, config, bob)
	if res.Value != false {
		t.Errorf("all: want false, got %v", res.Value)
	}
	if res.Reason.Source != ReasonCombined {
		t.Errorf("all: want source %s, got %s", ReasonCombined, res.Reason.Source)
	}
}

func TestEnumRankMax(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:    templates.TypeEnum,
		Resolve: templates.ResolveMax,
		Choices: []templates.EnumOption{
			{Value: "viewer", Label: "Viewer"},
			{Value: "editor", Label: "Editor"},
			{Value: "admin", Label: "Admin"},
		},
	}

	rows := []Row{
		{Group: "editors", GroupID: 5, Value: "editor"},
		{Group: "admins", GroupID: 7, Value: "admin"},
	}
	config := PersonConfig{Default: "viewer", Rule: o.Resolve, Rows: rows}

	bob := Person{
		User:   "bob",
		Groups: map[string]int{"editors": 5, "admins": 7},
	}

	res := r.Resolve(o, config, bob)
	if res.Value != "admin" {
		t.Errorf("want admin, got %v", res.Value)
	}
	if res.Reason.Group != "admins" {
		t.Errorf("want group admins, got %s", res.Reason.Group)
	}
}

func TestRowIDMismatchGrantsNothing(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:    templates.TypeInt,
		Resolve: templates.ResolveMax,
	}

	// Row says office_milan has id 7, but person's Groups say it's 9
	config := PersonConfig{
		Default: int64(100),
		Rule:    o.Resolve,
		Rows: []Row{
			{Group: "office_milan", GroupID: 7, Value: int64(500)},
		},
	}

	alice := Person{
		User:   "alice",
		Groups: map[string]int{"office_milan": 9}, // mismatch!
	}

	res := r.Resolve(o, config, alice)
	// The row is skipped, so alice gets the default
	if res.Value != int64(100) {
		t.Errorf("want default 100, got %v", res.Value)
	}
	if res.Reason.Source != ReasonDefault {
		t.Errorf("want source %s, got %s", ReasonDefault, res.Reason.Source)
	}
}

func TestIncomparableValues(t *testing.T) {
	r := NewRegistry()

	// Under min: stale value triggers fail-closed to lowest-ranked choice
	o := &templates.Option{
		Type:    templates.TypeEnum,
		Resolve: templates.ResolveMin,
		Choices: []templates.EnumOption{
			{Value: "viewer", Label: "Viewer"},
			{Value: "editor", Label: "Editor"},
		},
	}

	// Row has a stale enum value "admin" not in choices
	config := PersonConfig{
		Default: "viewer",
		Rule:    o.Resolve,
		Rows: []Row{
			{Group: "editors", GroupID: 5, Value: "admin"}, // incomparable (stale)
		},
	}

	bob := Person{
		User:   "bob",
		Groups: map[string]int{"editors": 5},
	}

	res := r.Resolve(o, config, bob)
	// Fail closed: lowest-ranked choice (viewer)
	if res.Value != "viewer" {
		t.Errorf("fail-closed under min: want viewer (lowest), got %v", res.Value)
	}
	if res.Reason.Source != "fail-closed" {
		t.Errorf("fail-closed under min: want source fail-closed, got %s", res.Reason.Source)
	}
	// Stale row should be in Others
	if len(res.Reason.Others) != 1 || res.Reason.Others[0].Group != "editors" {
		t.Errorf("fail-closed: want stale row in Others, got %v", res.Reason.Others)
	}

	// Under max: stale values are dropped
	o.Resolve = templates.ResolveMax
	config.Rule = o.Resolve
	config.Rows = []Row{
		{Group: "editors", GroupID: 5, Value: "editor"},
		{Group: "admins", GroupID: 7, Value: "admin"}, // stale
	}
	alice := Person{
		User:   "alice",
		Groups: map[string]int{"editors": 5, "admins": 7},
	}

	res = r.Resolve(o, config, alice)
	// Only comparable value wins
	if res.Value != "editor" {
		t.Errorf("max with stale: want editor, got %v", res.Value)
	}
	if res.Reason.Group != "editors" {
		t.Errorf("max with stale: want group editors, got %s", res.Reason.Group)
	}
	// Stale row should be in Others
	if len(res.Reason.Others) != 1 || res.Reason.Others[0].Group != "admins" {
		t.Errorf("max with stale: want stale row in Others, got %v", res.Reason.Others)
	}
}

func TestDedupeFirstRowDecides(t *testing.T) {
	r := NewRegistry()
	o := &templates.Option{
		Type:    templates.TypeInt,
		Resolve: templates.ResolveMax,
	}

	// Two rows for office_milan: first has id 7 (matches), second has id 9 (wrong)
	// First row should decide even though its id matches
	config := PersonConfig{
		Default: int64(100),
		Rule:    o.Resolve,
		Rows: []Row{
			{Group: "office_milan", GroupID: 7, Value: int64(500)},
			{Group: "office_milan", GroupID: 9, Value: int64(999)}, // duplicate, wrong id
		},
	}

	alice := Person{
		User:   "alice",
		Groups: map[string]int{"office_milan": 7},
	}

	res := r.Resolve(o, config, alice)
	// First row matches and decides
	if res.Value != int64(500) {
		t.Errorf("dedupe: want 500 (first row), got %v", res.Value)
	}

	// Now test with first row having wrong id
	config.Rows = []Row{
		{Group: "office_milan", GroupID: 9, Value: int64(999)}, // first, wrong id
		{Group: "office_milan", GroupID: 7, Value: int64(500)}, // second, correct id
	}

	res = r.Resolve(o, config, alice)
	// First row decides (doesn't match), so alice gets default
	if res.Value != int64(100) {
		t.Errorf("dedupe first wrong: want default 100, got %v", res.Value)
	}
	if res.Reason.Source != ReasonDefault {
		t.Errorf("dedupe first wrong: want source %s, got %s", ReasonDefault, res.Reason.Source)
	}
}

func TestEffects(t *testing.T) {
	tests := []struct {
		name   string
		inputs []string
		want   string
	}{
		{"none and reload", []string{EffectNone, EffectReload}, EffectReload},
		{"reload, restart, none", []string{EffectReload, EffectRestart, EffectNone}, EffectRestart},
		{"all none", []string{EffectNone, EffectNone}, EffectNone},
		{"restart wins", []string{EffectReload, EffectRestart}, EffectRestart},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Strongest(tt.inputs...)
			if got != tt.want {
				t.Errorf("Strongest(%v) = %s, want %s", tt.inputs, got, tt.want)
			}
		})
	}

	// Test EffectOf
	effectTests := []struct {
		applies string
		want    string
	}{
		{templates.AppliesLive, EffectNone},
		{templates.AppliesNextRequest, EffectNone},
		{templates.AppliesNextSignIn, EffectNone},
		{templates.AppliesAccountCreation, EffectNone},
		{templates.AppliesReload, EffectReload},
		{templates.AppliesRestart, EffectRestart},
		{"unknown", EffectRestart}, // fail safe
	}

	for _, tt := range effectTests {
		t.Run("EffectOf_"+tt.applies, func(t *testing.T) {
			got := EffectOf(tt.applies)
			if got != tt.want {
				t.Errorf("EffectOf(%s) = %s, want %s", tt.applies, got, tt.want)
			}
		})
	}
}

func TestCheckRequires(t *testing.T) {
	spec := &templates.SettingsSpec{
		Options: []templates.Option{
			{
				Key:      "craft_version",
				Type:     templates.TypeString,
				Scope:    templates.ScopeInstance,
				Requires: []string{"craft_sha256"},
			},
			{
				Key:   "craft_sha256",
				Type:  templates.TypeString,
				Scope: templates.ScopeInstance,
			},
		},
	}

	// craft_version is set but craft_sha256 is empty → error
	values := map[string]Value{
		"craft_version": "1.0.0",
		"craft_sha256":  "",
	}
	err := CheckRequires(spec, values)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	// Error should mention both keys
	if !strings.Contains(err.Error(), "craft_version") || !strings.Contains(err.Error(), "craft_sha256") {
		t.Errorf("error should name both options, got: %v", err)
	}

	// Both empty → OK
	values = map[string]Value{
		"craft_version": "",
		"craft_sha256":  "",
	}
	if err := CheckRequires(spec, values); err != nil {
		t.Errorf("both empty: want nil, got %v", err)
	}

	// Both set → OK
	values = map[string]Value{
		"craft_version": "1.0.0",
		"craft_sha256":  "abc123",
	}
	if err := CheckRequires(spec, values); err != nil {
		t.Errorf("both set: want nil, got %v", err)
	}
}
