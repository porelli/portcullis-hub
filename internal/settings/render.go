package settings

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/templates"
	"gopkg.in/yaml.v3"
)

// Rendered is a value as one delivery takes it (§13.5).
type Rendered struct {
	// Text: the env value, header or claim attribute.
	Text string
	// JSON: the value in data files and hook stdin.
	JSON any
	// textErr: why Text can't be used as a single value (multi-line csv /
	// yaml, an item holding the default separator). Files and hooks don't
	// read Text; RenderDelivery refuses it for env, header and claim.
	textErr error
}

// Size render units: binary (1024) and decimal (1000), strictly (P15:
// GB = 10^9, GiB = 2^30).
var sizeRenderUnits = map[string]int64{
	"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
	"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
}

// Duration render units (seconds).
var durationRenderUnits = map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}

// Header and claim value limits (bytes).
const (
	MaxHeaderValue = 1024
	MaxClaimValue  = 4096
)

func listLike(typ string) bool {
	switch typ {
	case templates.TypeList, templates.TypeMultiEnum, templates.TypeGroups, templates.TypeUsers:
		return true
	}
	return false
}

// RenderOf is d's render (inside a claim, header or file; on the delivery
// for env and hook); nil = the defaults.
func RenderOf(d *templates.Delivery) *templates.Render {
	switch {
	case d.Claim != nil:
		return d.Claim.Render
	case d.Header != nil:
		return d.Header.Render
	case d.File != nil:
		return d.File.Render
	}
	return d.Render
}

// DeliveryName names d in errors: "env NAME", "claim name", …
func DeliveryName(d *templates.Delivery) string {
	switch {
	case d.Env != "":
		return "env " + d.Env
	case d.Claim != nil:
		return "claim " + d.Claim.Name
	case d.Header != nil:
		return "header " + d.Header.Name
	case d.File != nil:
		return "file " + d.File.Name
	case d.Hook != "":
		return "hook " + d.Hook
	}
	return "delivery"
}

// checkRenders checks each delivery's render against o's type (CheckOption).
func checkRenders(o *templates.Option) error {
	if o.Type == templates.TypeSize && o.AllowUnlimited && len(o.Delivery) == 0 {
		return fmt.Errorf("allow_unlimited needs deliveries that say how unlimited is rendered (render.unlimited)")
	}
	for i := range o.Delivery {
		d := &o.Delivery[i]
		if err := checkRender(o, d, RenderOf(d)); err != nil {
			return fmt.Errorf("%s: render: %w", DeliveryName(d), err)
		}
	}
	return checkUnlimitedReach(o)
}

// checkUnlimitedReach refuses allow_unlimited when a delivery's numeric
// render.unlimited is also what a value within the option's bounds
// renders as: the app would take that value for unlimited (and under
// resolve: min a restrictive row would win as the smallest).
func checkUnlimitedReach(o *templates.Option) error {
	if o.Type != templates.TypeSize || !o.AllowUnlimited {
		return nil
	}
	b, err := readBounds(o, parseSize)
	if err != nil {
		return nil // the kind's own check reports it
	}
	for i := range o.Delivery {
		d := &o.Delivery[i]
		r := RenderOf(d)
		if r == nil || r.Unlimited == nil {
			continue
		}
		n, err := strconv.ParseInt(*r.Unlimited, 10, 64)
		if err != nil || n < 0 {
			continue // not a number, or below any size
		}
		div := int64(1)
		if r.Unit != "" {
			div = sizeRenderUnits[r.Unit]
		}
		if div == 0 || n > math.MaxInt64/div {
			continue
		}
		v := n * div
		if (b.min == nil || v >= *b.min) && (b.max == nil || v <= *b.max) {
			return fmt.Errorf("allow_unlimited: %s renders unlimited as %s, which the value %s also renders as (set min above it, or render unlimited as a value no size reaches)", DeliveryName(d), *r.Unlimited, showSize(v))
		}
	}
	return nil
}

// envUnsafe: characters a single-quoted env value can't carry.
const envUnsafe = "'\\\n\r"

// CheckEnvText refuses text an env delivery can't carry single-quoted
// (a ' or \, a line break). fromJSON: the text is a JSON rendering, so a
// backslash came from JSON's escaping and the message says so.
func CheckEnvText(text string, fromJSON bool) error {
	if !strings.ContainsAny(text, envUnsafe) {
		return nil
	}
	if fromJSON && strings.Contains(text, "\\") {
		return fmt.Errorf("the JSON text contains a backslash (JSON escapes a double quote, a backslash and control characters inside strings as \\…), which an env value can't carry (use a file or hook delivery)")
	}
	return fmt.Errorf("the value contains a single quote, a backslash or a line break, which an env value can't carry (use a file or hook delivery)")
}

// EnvJSON: env delivery d of o carries JSON text (format json; a table's
// default rendering).
func EnvJSON(o *templates.Option, d *templates.Delivery) bool {
	r := RenderOf(d)
	return (r != nil && r.Format == templates.RenderJSON) || (o.Type == templates.TypeTable && (r == nil || r.Format == ""))
}

// valueDeliveries are o's deliveries, the implicit env UPPER(key) of an
// instance option without any included.
func valueDeliveries(o *templates.Option) []templates.Delivery {
	if len(o.Delivery) == 0 {
		if n := o.EnvName(); n != "" {
			return []templates.Delivery{{Env: n}}
		}
	}
	return o.Delivery
}

// checkValueDeliveries renders v (a default or a group_values value)
// through every delivery of o as the runtime would, the env quote rule
// included: a value no delivery can take is refused up front.
func checkValueDeliveries(o *templates.Option, v Value) error {
	for _, d := range valueDeliveries(o) {
		if strings.HasSuffix(d.Env, templates.IndexSuffix) {
			items, err := RenderIndexed(o, v, &d)
			if err != nil {
				return err
			}
			for i, it := range items {
				if err := CheckEnvText(it, false); err != nil {
					return fmt.Errorf("%s: item %d: %w", DeliveryName(&d), i+1, err)
				}
			}
			continue
		}
		r, err := RenderDelivery(o, v, &d)
		if err != nil {
			return err
		}
		if d.Env != "" {
			if err := CheckEnvText(r.Text, EnvJSON(o, &d)); err != nil {
				return fmt.Errorf("%s: %w", DeliveryName(&d), err)
			}
		}
	}
	return nil
}

func checkRender(o *templates.Option, d *templates.Delivery, r *templates.Render) error {
	if r == nil {
		r = &templates.Render{}
	}
	t := o.Type
	if d.Env != "" {
		for _, x := range []struct {
			name string
			v    *string
		}{{"true", r.True}, {"false", r.False}, {"unlimited", r.Unlimited}, {"join", r.Join}} {
			if x.v != nil && strings.ContainsAny(*x.v, "'\\") {
				return fmt.Errorf("%s must not contain a single quote or a backslash (an env value is single-quoted)", x.name)
			}
		}
	}
	if (r.Format == templates.RenderYAML || r.Format == templates.RenderCSV) && (d.Env != "" || d.Header != nil || d.Claim != nil) {
		return fmt.Errorf("format %s is multi-line: an env, header or claim delivery takes one line (use format: json or join)", r.Format)
	}
	switch {
	case r.Unit == "":
	case t == templates.TypeSize:
		if _, ok := sizeRenderUnits[r.Unit]; !ok {
			return fmt.Errorf("unit %q must be B, KiB, MiB, GiB, TiB, KB, MB, GB or TB", r.Unit)
		}
	case t == templates.TypeDuration:
		if _, ok := durationRenderUnits[r.Unit]; !ok {
			return fmt.Errorf("unit %q must be s, m, h or d", r.Unit)
		}
	case t == templates.TypeInt:
		if r.Unit != o.Unit {
			return fmt.Errorf("unit %q must be the option's unit %q (an int is not converted)", r.Unit, o.Unit)
		}
	default:
		return fmt.Errorf("unit is for size, duration and int options")
	}
	if r.Integer && t != templates.TypeSize && t != templates.TypeDuration {
		return fmt.Errorf("integer is for size and duration options")
	}
	if r.Unlimited != nil {
		if t != templates.TypeSize || !o.AllowUnlimited {
			return fmt.Errorf("unlimited is for size options with allow_unlimited")
		}
		if *r.Unlimited == "" || hasControl(*r.Unlimited) {
			return fmt.Errorf("unlimited must be a non-empty single-line string")
		}
	} else if t == templates.TypeSize && o.AllowUnlimited {
		return fmt.Errorf("allow_unlimited needs render.unlimited (the value the app takes for unlimited, e.g. \"-1\")")
	}
	for _, b := range []struct {
		name string
		v    *string
	}{{"true", r.True}, {"false", r.False}} {
		if b.v == nil {
			continue
		}
		if t != templates.TypeBool {
			return fmt.Errorf("%s is for bool options", b.name)
		}
		if hasControl(*b.v) {
			return fmt.Errorf("%s must be a single-line string", b.name)
		}
	}
	// A person_entered env delivery renders the collection of everyone's
	// values (§13.13): join and the list formats fit any of its types.
	pe := o.EffectiveScope() == templates.ScopePersonEntered
	collection := listLike(t) || pe
	if r.Join != nil {
		if !collection {
			return fmt.Errorf("join is for list, multi_enum, groups and users options (and person_entered collections)")
		}
		if *r.Join == "" || hasControl(*r.Join) {
			return fmt.Errorf("join must be a non-empty separator without newlines or control characters")
		}
		if r.Format != "" {
			return fmt.Errorf("join and format exclude each other")
		}
	}
	if r.ExpandMembers {
		if t != templates.TypeGroup && t != templates.TypeGroups || o.EffectiveScope() != templates.ScopeInstance {
			return fmt.Errorf("expand_members is for group and groups options of scope instance")
		}
		if d.File == nil {
			return fmt.Errorf("expand_members is for file deliveries (a data file holds the members)")
		}
		if r.Join != nil || r.Format != "" {
			return fmt.Errorf("expand_members renders the member list: no join or format")
		}
	}
	switch r.Format {
	case "", templates.RenderJSON:
	case templates.RenderYAML, templates.RenderCSV:
		// Only env carries a person_entered collection; elsewhere it is
		// the person's own (scalar) value.
		if !listLike(t) && t != templates.TypeTable {
			if pe {
				return fmt.Errorf("format %s is for list and table values: outside env a person_entered %s is the person's own value", r.Format, t)
			}
			return fmt.Errorf("format %s is for list, multi_enum, groups, users and table options (and person_entered collections)", r.Format)
		}
	default:
		return fmt.Errorf("format %q must be json, yaml or csv", r.Format)
	}
	return nil
}

// Render renders the canonical v for one delivery's render rd (nil = the
// defaults). Errors name the unit or sentinel that doesn't fit; the
// caller adds the app and delivery (RenderDelivery adds the delivery).
func Render(o *templates.Option, v Value, rd *templates.Render) (Rendered, error) {
	if rd == nil {
		rd = &templates.Render{}
	}
	if rd.Join != nil && (*rd.Join == "" || hasControl(*rd.Join)) {
		return Rendered{}, fmt.Errorf("join must be a non-empty separator without a newline or control characters")
	}
	var out Rendered
	var err error
	switch o.Type {
	case templates.TypeSize:
		out, err = renderSize(o, v, rd)
	case templates.TypeDuration:
		n, ok := v.(int64)
		if !ok {
			return Rendered{}, fmt.Errorf("not a duration: %T", v)
		}
		unit := rd.Unit
		if unit == "" {
			unit = "s"
		}
		div, ok := durationRenderUnits[unit]
		if !ok {
			return Rendered{}, fmt.Errorf("unknown duration unit %q", unit)
		}
		out, err = divide(n, div, unit, showDuration(n), rd.Integer)
	case templates.TypeInt:
		n, ok := v.(int64)
		if !ok {
			return Rendered{}, fmt.Errorf("not an int: %T", v)
		}
		out = Rendered{Text: strconv.FormatInt(n, 10), JSON: n}
	case templates.TypeBool:
		b, ok := v.(bool)
		if !ok {
			return Rendered{}, fmt.Errorf("not a bool: %T", v)
		}
		out = Rendered{Text: strconv.FormatBool(b), JSON: b}
		if rd.True != nil || rd.False != nil {
			s := strconv.FormatBool(b)
			if b && rd.True != nil {
				s = *rd.True
			} else if !b && rd.False != nil {
				s = *rd.False
			}
			out = Rendered{Text: s, JSON: s}
		}
	case templates.TypeString, templates.TypeEnum, templates.TypeSecret, templates.TypePath,
		templates.TypeGroup, templates.TypeUser:
		s, ok := v.(string)
		if !ok {
			return Rendered{}, fmt.Errorf("not a string: %T", v)
		}
		out = Rendered{Text: s, JSON: s}
	case templates.TypeList, templates.TypeMultiEnum, templates.TypeGroups, templates.TypeUsers:
		return renderList(v, rd)
	case templates.TypeTable:
		return renderTable(o, v, rd)
	default:
		return Rendered{}, fmt.Errorf("type %s has no renderer", o.Type)
	}
	if err != nil {
		return Rendered{}, err
	}
	switch rd.Format {
	case "":
	case templates.RenderJSON:
		t, err := JSONText(out.JSON)
		if err != nil {
			return Rendered{}, err
		}
		out.Text = t
	default:
		return Rendered{}, fmt.Errorf("format %s is for list and table options", rd.Format)
	}
	if hasControl(out.Text) {
		return Rendered{}, fmt.Errorf("the rendered value contains a newline or control characters")
	}
	return out, nil
}

func renderSize(o *templates.Option, v Value, rd *templates.Render) (Rendered, error) {
	if v == (Unlimited{}) {
		if !o.AllowUnlimited {
			return Rendered{}, fmt.Errorf("unlimited is not allowed for this option")
		}
		if rd.Unlimited == nil {
			return Rendered{}, fmt.Errorf("the delivery has no render.unlimited: it can't take unlimited")
		}
		s := *rd.Unlimited
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return Rendered{Text: s, JSON: n}, nil
		}
		return Rendered{Text: s, JSON: s}, nil
	}
	n, ok := v.(int64)
	if !ok {
		return Rendered{}, fmt.Errorf("not a size: %T", v)
	}
	unit := rd.Unit
	if unit == "" {
		unit = "B"
	}
	div, ok := sizeRenderUnits[unit]
	if !ok {
		return Rendered{}, fmt.Errorf("unknown size unit %q", unit)
	}
	return divide(n, div, unit, showSize(n), rd.Integer)
}

// divide renders n / div exactly: an int64 when whole, else a decimal
// (refused with integer: true, naming the unit).
func divide(n, div int64, unit, shown string, integer bool) (Rendered, error) {
	if n%div == 0 {
		q := n / div
		return Rendered{Text: strconv.FormatInt(q, 10), JSON: q}, nil
	}
	if integer {
		return Rendered{}, fmt.Errorf("%s is not a whole number of %s: the app takes whole %s", shown, unit, unit)
	}
	f, _ := new(big.Rat).SetFrac64(n, div).Float64()
	return Rendered{Text: strconv.FormatFloat(f, 'f', -1, 64), JSON: f}, nil
}

func itemText(v Value) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func renderList(v Value, rd *templates.Render) (Rendered, error) {
	l, ok := v.([]Value)
	if !ok {
		return Rendered{}, fmt.Errorf("not a list: %T", v)
	}
	items := make([]any, len(l))
	texts := make([]string, len(l))
	for i, it := range l {
		items[i] = it
		texts[i] = itemText(it)
	}
	switch rd.Format {
	case templates.RenderJSON:
		t, err := JSONText(items)
		if err != nil {
			return Rendered{}, err
		}
		return Rendered{Text: t, JSON: items}, nil
	case templates.RenderYAML:
		b, err := yaml.Marshal(items)
		if err != nil {
			return Rendered{}, err
		}
		return multiLine(string(b)), nil
	case templates.RenderCSV:
		s, err := csvLines([][]string{texts})
		if err != nil {
			return Rendered{}, err
		}
		s = strings.TrimSuffix(s, "\n")
		return multiLine(s), nil
	case "":
	default:
		return Rendered{}, fmt.Errorf("unknown format %q", rd.Format)
	}
	sep := ","
	if rd.Join != nil {
		sep = *rd.Join
	}
	var clash error
	for _, s := range texts {
		if sep != "" && strings.Contains(s, sep) {
			clash = fmt.Errorf("item %q contains the separator %q", s, sep)
			break
		}
	}
	joined := strings.Join(texts, sep)
	if rd.Join != nil {
		if clash != nil {
			return Rendered{}, clash
		}
		return Rendered{Text: joined, JSON: joined}, nil
	}
	// No render: files and hooks get the list, env / headers the
	// comma-joined text (unusable when an item holds a comma).
	return Rendered{Text: joined, JSON: items, textErr: clash}, nil
}

// JSONText is v as compact JSON without HTML escaping (json.Marshal
// writes & < > as \u0026 …, whose backslash an env value can't carry).
func JSONText(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// multiLine is structured text: the same string for files and hooks, and
// unusable as a single env / header / claim value when it spans lines.
func multiLine(s string) Rendered {
	r := Rendered{Text: s, JSON: s}
	if hasControl(s) {
		r.textErr = fmt.Errorf("the rendered value contains a newline (use format: json for a single-line value)")
	}
	return r
}

func csvLines(rows [][]string) (string, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.WriteAll(rows); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderTable(o *templates.Option, v Value, rd *templates.Render) (Rendered, error) {
	rows, ok := v.([]map[string]Value)
	if !ok {
		return Rendered{}, fmt.Errorf("not a table: %T", v)
	}
	var structured any
	if o.KeyColumn != "" {
		m := map[string]any{}
		for _, r := range rows {
			m[itemText(r[o.KeyColumn])] = map[string]any(r)
		}
		structured = m
	} else {
		l := make([]any, len(rows))
		for i, r := range rows {
			l[i] = map[string]any(r)
		}
		structured = l
	}
	switch rd.Format {
	case "", templates.RenderJSON:
		t, err := JSONText(structured)
		if err != nil {
			return Rendered{}, err
		}
		return Rendered{Text: t, JSON: structured}, nil
	case templates.RenderYAML:
		b, err := yaml.Marshal(structured)
		if err != nil {
			return Rendered{}, err
		}
		return multiLine(string(b)), nil
	case templates.RenderCSV:
		header := make([]string, len(o.Columns))
		for i, c := range o.Columns {
			header[i] = c.Name
		}
		lines := [][]string{header}
		for _, r := range rows {
			line := make([]string, len(o.Columns))
			for i, c := range o.Columns {
				if cv, ok := r[c.Name]; ok {
					line[i] = itemText(cv)
				}
			}
			lines = append(lines, line)
		}
		s, err := csvLines(lines)
		if err != nil {
			return Rendered{}, err
		}
		return multiLine(s), nil
	}
	return Rendered{}, fmt.Errorf("unknown format %q", rd.Format)
}

// RenderDelivery renders v for delivery d with d's render. Env, header
// and claim values are single lines; a header is at most MaxHeaderValue
// bytes and a claim attribute MaxClaimValue. Errors name the delivery.
func RenderDelivery(o *templates.Option, v Value, d *templates.Delivery) (Rendered, error) {
	name := DeliveryName(d)
	out, err := Render(o, v, RenderOf(d))
	if err != nil {
		return Rendered{}, fmt.Errorf("%s: %w", name, err)
	}
	if d.Env == "" && d.Header == nil && d.Claim == nil {
		return out, nil
	}
	if out.textErr != nil {
		return Rendered{}, fmt.Errorf("%s: %w", name, out.textErr)
	}
	if hasControl(out.Text) {
		return Rendered{}, fmt.Errorf("%s: the rendered value contains a newline or control characters", name)
	}
	switch {
	case d.Header != nil && len(out.Text) > MaxHeaderValue:
		return Rendered{}, fmt.Errorf("%s: the rendered value is %d bytes, over the %d-byte header limit", name, len(out.Text), MaxHeaderValue)
	case d.Claim != nil && len(out.Text) > MaxClaimValue:
		return Rendered{}, fmt.Errorf("%s: the rendered value is %d bytes, over the %d-byte claim attribute limit", name, len(out.Text), MaxClaimValue)
	}
	return out, nil
}

// RenderIndexed renders a list v for an indexed env delivery d
// (NAME_{n}, §13.6): one single-line text per item, each rendered on its
// own (never joined, so no separator can clash). More items than
// max_items are refused.
func RenderIndexed(o *templates.Option, v Value, d *templates.Delivery) ([]string, error) {
	name := DeliveryName(d)
	l, ok := v.([]Value)
	if !ok {
		return nil, fmt.Errorf("%s: not a list: %T", name, v)
	}
	if o.MaxItems == nil || len(l) > *o.MaxItems {
		return nil, fmt.Errorf("%s: %d items don't fit its max_items", name, len(l))
	}
	out := make([]string, len(l))
	for i, it := range l {
		s := itemText(it)
		if hasControl(s) {
			return nil, fmt.Errorf("%s: item %d contains a newline or control characters", name, i+1)
		}
		out[i] = s
	}
	return out, nil
}
