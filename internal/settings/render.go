package settings

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
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
		if err := checkRender(o, RenderOf(d)); err != nil {
			return fmt.Errorf("%s: render: %w", DeliveryName(d), err)
		}
	}
	return nil
}

func checkRender(o *templates.Option, r *templates.Render) error {
	if r == nil {
		r = &templates.Render{}
	}
	t := o.Type
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
	collection := listLike(t) || o.EffectiveScope() == templates.ScopePersonEntered
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
	switch r.Format {
	case "", templates.RenderJSON:
	case templates.RenderYAML, templates.RenderCSV:
		if !collection && t != templates.TypeTable {
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
		b, err := json.Marshal(out.JSON)
		if err != nil {
			return Rendered{}, err
		}
		out.Text = string(b)
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
		b, err := json.Marshal(items)
		if err != nil {
			return Rendered{}, err
		}
		return Rendered{Text: string(b), JSON: items}, nil
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
		b, err := json.Marshal(structured)
		if err != nil {
			return Rendered{}, err
		}
		return Rendered{Text: string(b), JSON: structured}, nil
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
