package settings

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/templates"
)

// maxItems bounds every list-like value (§13.2: min_items / max_items 0–1000).
const maxItems = 1000

// toList reads a decoded sequence.
func toList(raw any) ([]any, error) {
	switch x := raw.(type) {
	case []any:
		return x, nil
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, nil
	}
	return nil, fmt.Errorf("want a list, not %T", raw)
}

func checkItemBounds(o *templates.Option) error {
	for _, f := range []struct {
		name string
		v    *int
	}{{"min_items", o.MinItems}, {"max_items", o.MaxItems}} {
		if f.v != nil && (*f.v < 0 || *f.v > maxItems) {
			return fmt.Errorf("%s must be 0-%d", f.name, maxItems)
		}
	}
	if o.MinItems != nil && o.MaxItems != nil && *o.MinItems > *o.MaxItems {
		return fmt.Errorf("min_items is above max_items")
	}
	return nil
}

func countItems(o *templates.Option, n int) error {
	if n > maxItems {
		return fmt.Errorf("at most %d items", maxItems)
	}
	if o.MinItems != nil && n < *o.MinItems {
		return fmt.Errorf("needs at least %d items", *o.MinItems)
	}
	if o.MaxItems != nil && n > *o.MaxItems {
		return fmt.Errorf("takes at most %d items", *o.MaxItems)
	}
	return nil
}

// itemKey identifies a canonical scalar for duplicate checks.
func itemKey(v Value) string { return fmt.Sprintf("%T:%v", v, v) }

func joinDisplay(vs []string) string { return strings.Join(vs, ", ") }

// ── multi_enum ───────────────────────────────────────────

type multiEnumKind struct{}

func (multiEnumKind) Name() string { return templates.TypeMultiEnum }

func (multiEnumKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "options", "min_items", "max_items"); err != nil {
		return err
	}
	if err := checkChoices(o.Choices); err != nil {
		return err
	}
	return checkItemBounds(o)
}

// Parse: a set; duplicates collapse, the canonical order is the options'.
func (multiEnumKind) Parse(o *templates.Option, raw any) (Value, error) {
	l, err := toList(raw)
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	for _, it := range l {
		s, err := parseChoice(o.Choices, it)
		if err != nil {
			return nil, err
		}
		in[s] = true
	}
	out := []Value{}
	for _, c := range o.Choices {
		if in[c.Value] {
			out = append(out, c.Value)
		}
	}
	if err := countItems(o, len(out)); err != nil {
		return nil, err
	}
	return out, nil
}

func (multiEnumKind) Display(o *templates.Option, v Value) string {
	l, _ := v.([]Value)
	var out []string
	for _, it := range l {
		out = append(out, enumKind{}.Display(o, it))
	}
	return joinDisplay(out)
}

func (multiEnumKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// ── list ─────────────────────────────────────────────────

type listKind struct{}

func (listKind) Name() string { return templates.TypeList }

// listItemTypes are the item types a list (and a table column) may have.
var listItemTypes = map[string]Kind{
	templates.TypeString: stringKind{}, templates.TypeInt: intKind{},
	templates.TypeBool: boolKind{}, templates.TypeEnum: enumKind{},
}

// itemOption is a list's item type as an option of its own, so the
// scalar kinds check and parse it.
func itemOption(o *templates.Option) *templates.Option {
	it := o.Items
	if it == nil {
		return &templates.Option{Key: o.Key, Type: ""}
	}
	return &templates.Option{
		Key: o.Key, Type: it.Type, Pattern: it.Pattern, Format: it.Format,
		MinLen: it.MinLen, MaxLen: it.MaxLen, Min: it.Min, Max: it.Max, Choices: it.Choices,
	}
}

func (listKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "items", "min_items", "max_items"); err != nil {
		return err
	}
	if o.Items == nil {
		return fmt.Errorf("a list needs items: {type: string | int | bool | enum}")
	}
	io := itemOption(o)
	k := listItemTypes[io.Type]
	if k == nil {
		return fmt.Errorf("items: type %q must be string, int, bool or enum", io.Type)
	}
	if err := k.CheckOption(io); err != nil {
		return fmt.Errorf("items: %w", err)
	}
	return checkItemBounds(o)
}

func (listKind) Parse(o *templates.Option, raw any) (Value, error) {
	l, err := toList(raw)
	if err != nil {
		return nil, err
	}
	io := itemOption(o)
	k := listItemTypes[io.Type]
	if k == nil {
		return nil, fmt.Errorf("items: unknown type %q", io.Type)
	}
	if err := countItems(o, len(l)); err != nil {
		return nil, err
	}
	out := make([]Value, 0, len(l))
	seen := map[string]bool{}
	for i, it := range l {
		v, err := k.Parse(io, it)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i+1, err)
		}
		if o.Unique {
			if seen[itemKey(v)] {
				return nil, fmt.Errorf("item %d: duplicate %v (items must be unique)", i+1, v)
			}
			seen[itemKey(v)] = true
		}
		out = append(out, v)
	}
	return out, nil
}

func (listKind) Display(o *templates.Option, v Value) string {
	l, _ := v.([]Value)
	io := itemOption(o)
	k := listItemTypes[io.Type]
	var out []string
	for _, it := range l {
		if k == nil {
			out = append(out, fmt.Sprint(it))
			continue
		}
		out = append(out, k.Display(io, it))
	}
	return joinDisplay(out)
}

func (listKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// ── table ────────────────────────────────────────────────

type tableKind struct{}

func (tableKind) Name() string { return templates.TypeTable }

var columnNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func columnOption(o *templates.Option, c *templates.Column) *templates.Option {
	return &templates.Option{
		Key: o.Key, Type: c.Type, Pattern: c.Pattern, Format: c.Format,
		MinLen: c.MinLen, MaxLen: c.MaxLen, Min: c.Min, Max: c.Max, Choices: c.Choices,
	}
}

func (tableKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "columns", "key_column", "min_items", "max_items"); err != nil {
		return err
	}
	if len(o.Columns) == 0 {
		return fmt.Errorf("a table needs at least one column")
	}
	seen := map[string]bool{}
	for i := range o.Columns {
		c := &o.Columns[i]
		if !columnNameRe.MatchString(c.Name) {
			return fmt.Errorf("columns: name %q must match %s", c.Name, columnNameRe)
		}
		if seen[c.Name] {
			return fmt.Errorf("columns: %s listed twice", c.Name)
		}
		seen[c.Name] = true
		if c.Label == "" || len(c.Label) > 64 || checkText(c.Label) != nil {
			return fmt.Errorf("columns: %s needs a single-line label of at most 64 characters", c.Name)
		}
		k := listItemTypes[c.Type]
		if k == nil {
			return fmt.Errorf("columns: %s: type %q must be string, int, bool or enum", c.Name, c.Type)
		}
		if err := k.CheckOption(columnOption(o, c)); err != nil {
			return fmt.Errorf("columns: %s: %w", c.Name, err)
		}
	}
	if o.KeyColumn != "" && !seen[o.KeyColumn] {
		return fmt.Errorf("key_column %s is not a column", o.KeyColumn)
	}
	return checkItemBounds(o)
}

func toRow(raw any) (map[string]any, bool) {
	switch x := raw.(type) {
	case map[string]any:
		return x, true
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = v
		}
		return out, true
	}
	return nil, false
}

func toRows(raw any) ([]any, error) {
	if rs, ok := raw.([]map[string]Value); ok {
		out := make([]any, len(rs))
		for i, r := range rs {
			out[i] = r
		}
		return out, nil
	}
	return toList(raw)
}

// Parse: rows of typed columns; a required column (and the key column)
// must be present and non-empty; key_column values are unique.
func (tableKind) Parse(o *templates.Option, raw any) (Value, error) {
	rows, err := toRows(raw)
	if err != nil {
		return nil, err
	}
	if err := countItems(o, len(rows)); err != nil {
		return nil, err
	}
	cols := map[string]*templates.Column{}
	for i := range o.Columns {
		cols[o.Columns[i].Name] = &o.Columns[i]
	}
	keys := map[string]int{}
	out := make([]map[string]Value, 0, len(rows))
	for i, r := range rows {
		row, ok := toRow(r)
		if !ok {
			return nil, fmt.Errorf("row %d: want a record {column: value}, not %T", i+1, r)
		}
		for _, name := range sortedKeys(row) {
			if cols[name] == nil {
				return nil, fmt.Errorf("row %d: %s is not a column", i+1, name)
			}
		}
		rec := map[string]Value{}
		for ci := range o.Columns {
			c := &o.Columns[ci]
			cv, present := row[c.Name]
			if !present || cv == nil || cv == "" {
				if c.Required || c.Name == o.KeyColumn {
					return nil, fmt.Errorf("row %d: %s is required", i+1, c.Name)
				}
				if !present || cv == nil {
					continue
				}
			}
			v, err := listItemTypes[c.Type].Parse(columnOption(o, c), cv)
			if err != nil {
				return nil, fmt.Errorf("row %d: %s: %w", i+1, c.Name, err)
			}
			rec[c.Name] = v
		}
		if o.KeyColumn != "" {
			k := itemKey(rec[o.KeyColumn])
			if j, dup := keys[k]; dup {
				return nil, fmt.Errorf("row %d: duplicate %s %v (also in row %d)", i+1, o.KeyColumn, rec[o.KeyColumn], j)
			}
			keys[k] = i + 1
		}
		out = append(out, rec)
	}
	return out, nil
}

func (tableKind) Display(_ *templates.Option, v Value) string {
	rs, _ := v.([]map[string]Value)
	if len(rs) == 1 {
		return "1 row"
	}
	return fmt.Sprintf("%d rows", len(rs))
}

func (tableKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// ── group / groups / user / users ────────────────────────

// nameKind is an LLDAP group name or username, one or a set.
type nameKind struct {
	name      string
	user, set bool
}

func (k nameKind) Name() string { return k.name }

func (k nameKind) CheckOption(o *templates.Option) error {
	if k.set {
		if err := onlyFields(o, "min_items", "max_items"); err != nil {
			return err
		}
		return checkItemBounds(o)
	}
	return onlyFields(o)
}

func (k nameKind) one(raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("want a name, not %T", raw)
	}
	if k.user {
		if strings.Contains(s, "@") {
			return "", fmt.Errorf("%q: want a username, not an email address", s)
		}
		// ASCII first: Unicode case folding maps K (Kelvin) to k and ſ
		// to s, so a fold could alias another account. LLDAP user ids are
		// lowercase.
		for i := 0; i < len(s); i++ {
			if s[i] >= 0x80 {
				return "", fmt.Errorf("%q is not a valid username (ASCII only)", s)
			}
		}
		u := strings.ToLower(s)
		if !lldap.ValidUsername(u) {
			return "", fmt.Errorf("%q is not a valid username", s)
		}
		return u, nil
	}
	if !lldap.ValidGroupName(s) {
		return "", fmt.Errorf("%q is not a valid group name", s)
	}
	return s, nil
}

func (k nameKind) Parse(o *templates.Option, raw any) (Value, error) {
	if !k.set {
		return k.one(raw)
	}
	l, err := toList(raw)
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	for i, it := range l {
		s, err := k.one(it)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i+1, err)
		}
		in[s] = true
	}
	names := sortedKeys(in)
	if err := countItems(o, len(names)); err != nil {
		return nil, err
	}
	out := make([]Value, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out, nil
}

func (k nameKind) Display(_ *templates.Option, v Value) string {
	if !k.set {
		s, _ := v.(string)
		return s
	}
	l, _ := v.([]Value)
	var out []string
	for _, it := range l {
		out = append(out, fmt.Sprint(it))
	}
	sort.Strings(out)
	return joinDisplay(out)
}

func (nameKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }
