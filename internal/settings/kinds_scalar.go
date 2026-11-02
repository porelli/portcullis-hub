package settings

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	units "github.com/docker/go-units"
	str2duration "github.com/xhit/go-str2duration/v2"

	"github.com/portcullis/hub/internal/templates"
)

// ── shared helpers ───────────────────────────────────────

// toInt reads an integral number decoded from YAML or JSON.
func toInt(raw any) (int64, error) {
	switch x := raw.(type) {
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		return uintToInt(uint64(x))
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		return uintToInt(x)
	case float32:
		return floatToInt(float64(x))
	case float64:
		return floatToInt(x)
	case json.Number:
		return parseDecimal(string(x))
	}
	return 0, fmt.Errorf("want a whole number, not %T", raw)
}

func uintToInt(u uint64) (int64, error) {
	if u > math.MaxInt64 {
		return 0, fmt.Errorf("%d is too large", u)
	}
	return int64(u), nil
}

func floatToInt(f float64) (int64, error) {
	if f != math.Trunc(f) || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("%v is not a whole number", f)
	}
	if f >= 1<<63 || f < -(1<<63) {
		return 0, fmt.Errorf("%v is too large", f)
	}
	return int64(f), nil
}

var decimalRe = regexp.MustCompile(`^-?[0-9]{1,19}$`)

func parseDecimal(s string) (int64, error) {
	if !decimalRe.MatchString(s) {
		return 0, fmt.Errorf("%q is not a whole number", s)
	}
	return strconv.ParseInt(s, 10, 64)
}

func isNumber(raw any) bool {
	switch raw.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return true
	}
	return false
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// hasControl: C0 controls and DEL (every newline form included).
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 })
}

// checkText is the rule every string value follows: valid UTF-8, no
// control characters.
func checkText(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("not valid UTF-8")
	}
	if hasControl(s) {
		return fmt.Errorf("contains control characters (newlines included)")
	}
	return nil
}

// bounds is an ordered kind's manifest min / max / step, canonical.
type bounds struct {
	min, max, step *int64
}

// readBounds parses o's min / max / step with parse (the kind's own
// input form) and checks min ≤ max, step > 0.
func readBounds(o *templates.Option, parse func(any) (int64, error)) (bounds, error) {
	var b bounds
	for _, f := range []struct {
		name string
		raw  any
		dst  **int64
	}{{"min", o.Min, &b.min}, {"max", o.Max, &b.max}, {"step", o.Step, &b.step}} {
		if f.raw == nil {
			continue
		}
		v, err := parse(f.raw)
		if err != nil {
			return b, fmt.Errorf("%s: %v", f.name, err)
		}
		*f.dst = &v
	}
	if b.min != nil && b.max != nil && *b.min > *b.max {
		return b, fmt.Errorf("min is above max")
	}
	if b.step != nil && *b.step <= 0 {
		return b, fmt.Errorf("step must be positive")
	}
	return b, nil
}

// check enforces the bounds on v; show formats numbers in messages. The
// step counts from min (0 without one).
func (b bounds) check(v int64, show func(int64) string) error {
	if b.min != nil && v < *b.min {
		return fmt.Errorf("must be at least %s", show(*b.min))
	}
	if b.max != nil && v > *b.max {
		return fmt.Errorf("must be at most %s", show(*b.max))
	}
	if b.step != nil {
		var base int64
		if b.min != nil {
			base = *b.min
		}
		// v ≥ base here when min is set; the unsigned difference is exact.
		var d uint64
		if v >= base {
			d = uint64(v) - uint64(base)
		} else {
			d = uint64(base) - uint64(v)
		}
		if d%uint64(*b.step) != 0 {
			if base != 0 {
				return fmt.Errorf("must be %s plus a multiple of %s", show(base), show(*b.step))
			}
			return fmt.Errorf("must be a multiple of %s", show(*b.step))
		}
	}
	return nil
}

// ── string ───────────────────────────────────────────────

type stringKind struct{}

func (stringKind) Name() string { return templates.TypeString }

// maxStringLen bounds min_len / max_len (characters).
const maxStringLen = 65535

var patternCache sync.Map // pattern → *regexp.Regexp (whole-value form)

// compilePattern checks a manifest pattern (anchored ^…$, ≤ 500) and
// returns it in its whole-value form ^(?:…)$, so alternation can't
// escape the anchors.
func compilePattern(p string) (*regexp.Regexp, error) {
	if re, ok := patternCache.Load(p); ok {
		return re.(*regexp.Regexp), nil
	}
	if len(p) > 500 {
		return nil, fmt.Errorf("pattern is longer than 500 characters")
	}
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		return nil, fmt.Errorf("pattern %q must be anchored: ^…$", p)
	}
	if _, err := regexp.Compile(p); err != nil {
		return nil, fmt.Errorf("pattern %q: %v", p, err)
	}
	re, err := regexp.Compile(`^(?:` + p + `)$`)
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %v", p, err)
	}
	patternCache.Store(p, re)
	return re, nil
}

func checkLens(minLen, maxLen *int) error {
	for _, f := range []struct {
		name string
		v    *int
	}{{"min_len", minLen}, {"max_len", maxLen}} {
		if f.v != nil && (*f.v < 0 || *f.v > maxStringLen) {
			return fmt.Errorf("%s must be 0-%d", f.name, maxStringLen)
		}
	}
	if minLen != nil && maxLen != nil && *minLen > *maxLen {
		return fmt.Errorf("min_len is above max_len")
	}
	return nil
}

func (stringKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "pattern", "format", "min_len", "max_len"); err != nil {
		return err
	}
	if o.Pattern != "" {
		if _, err := compilePattern(o.Pattern); err != nil {
			return err
		}
	}
	if o.Format != "" && formats[o.Format] == nil {
		return fmt.Errorf("format %q must be one of %s", o.Format, formatNames())
	}
	return checkLens(o.MinLen, o.MaxLen)
}

func (stringKind) Parse(o *templates.Option, raw any) (Value, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("want a string, not %T", raw)
	}
	if err := checkText(s); err != nil {
		return nil, err
	}
	n := utf8.RuneCountInString(s)
	if n > maxStringLen {
		return nil, fmt.Errorf("must be at most %d characters", maxStringLen)
	}
	if o.MinLen != nil && n < *o.MinLen {
		return nil, fmt.Errorf("must be at least %d characters", *o.MinLen)
	}
	if o.MaxLen != nil && n > *o.MaxLen {
		return nil, fmt.Errorf("must be at most %d characters", *o.MaxLen)
	}
	if o.Format != "" {
		f := formats[o.Format]
		if f == nil {
			return nil, fmt.Errorf("unknown format %q", o.Format)
		}
		if err := f(s); err != nil {
			return nil, fmt.Errorf("%q is not a valid %s: %v", s, o.Format, err)
		}
	}
	if o.Pattern != "" {
		re, err := compilePattern(o.Pattern)
		if err != nil {
			return nil, err
		}
		if !re.MatchString(s) {
			return nil, fmt.Errorf("%q doesn't match the pattern %s", s, o.Pattern)
		}
	}
	return s, nil
}

func (stringKind) Display(_ *templates.Option, v Value) string { s, _ := v.(string); return s }

func (stringKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// ── int ──────────────────────────────────────────────────

type intKind struct{}

func (intKind) Name() string { return templates.TypeInt }

func intInput(raw any) (int64, error) {
	if s, ok := raw.(string); ok {
		return parseDecimal(s)
	}
	return toInt(raw)
}

func (intKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "min", "max", "step", "unit"); err != nil {
		return err
	}
	if o.Unit != "" && (len(o.Unit) > 32 || hasControl(o.Unit)) {
		return fmt.Errorf("unit must be a single line of at most 32 characters")
	}
	_, err := readBounds(o, toInt)
	return err
}

func (intKind) Parse(o *templates.Option, raw any) (Value, error) {
	v, err := intInput(raw)
	if err != nil {
		return nil, err
	}
	b, err := readBounds(o, toInt)
	if err != nil {
		return nil, err
	}
	if err := b.check(v, func(n int64) string { return strconv.FormatInt(n, 10) }); err != nil {
		return nil, err
	}
	return v, nil
}

func (intKind) Display(o *templates.Option, v Value) string {
	n, _ := v.(int64)
	s := strconv.FormatInt(n, 10)
	if o.Unit != "" {
		s += " " + o.Unit
	}
	return s
}

func (intKind) Compare(_ *templates.Option, a, b Value) (int, bool) {
	x, ok1 := a.(int64)
	y, ok2 := b.(int64)
	return cmpInt(x, y), ok1 && ok2
}

// ── size ─────────────────────────────────────────────────

type sizeKind struct{}

func (sizeKind) Name() string { return templates.TypeSize }

// sizeInputRe: a number with an optional binary unit. Decimal and bare
// letter units (GB, G) are refused: GB means 10^9, never 2^30 (P15).
var sizeInputRe = regexp.MustCompile(`(?i)^([0-9]{1,20}(?:\.[0-9]{1,12})?) ?((?:[kmgtp]i)?b)?$`)

var sizeMultipliers = map[string]int64{"": 1, "b": 1, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40, "pib": 1 << 50}

// parseSize reads "10GiB", "10 GiB", "512" or a number of bytes.
func parseSize(raw any) (int64, error) {
	if isNumber(raw) {
		v, err := toInt(raw)
		if err != nil {
			return 0, err
		}
		if v < 0 {
			return 0, fmt.Errorf("a size can't be negative")
		}
		return v, nil
	}
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("want a size such as 10GiB, not %T", raw)
	}
	m := sizeInputRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("%q is not a size: use a number with B, KiB, MiB, GiB, TiB or PiB (binary units)", s)
	}
	v, err := units.RAMInBytes(s)
	if err != nil {
		return 0, fmt.Errorf("%q: %v", s, err)
	}
	// RAMInBytes goes through float64: confirm the exact value.
	exact, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return 0, fmt.Errorf("%q is not a size", s)
	}
	exact.Mul(exact, new(big.Rat).SetInt64(sizeMultipliers[strings.ToLower(m[2])]))
	if !exact.IsInt() || !exact.Num().IsInt64() || exact.Num().Int64() != v {
		return 0, fmt.Errorf("%q is not a whole number of bytes, or too large", s)
	}
	return v, nil
}

func (sizeKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "min", "max", "step", "allow_unlimited"); err != nil {
		return err
	}
	_, err := readBounds(o, parseSize)
	return err
}

func (sizeKind) Parse(o *templates.Option, raw any) (Value, error) {
	if raw == (Unlimited{}) || raw == UnlimitedText {
		if !o.AllowUnlimited {
			return nil, fmt.Errorf("unlimited is not allowed here")
		}
		return Unlimited{}, nil
	}
	v, err := parseSize(raw)
	if err != nil {
		return nil, err
	}
	b, err := readBounds(o, parseSize)
	if err != nil {
		return nil, err
	}
	if err := b.check(v, showSize); err != nil {
		return nil, err
	}
	return v, nil
}

var binaryLabels = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

func showSize(n int64) string { return units.CustomSize("%.4g %s", float64(n), 1024.0, binaryLabels) }

func (sizeKind) Display(_ *templates.Option, v Value) string {
	if v == (Unlimited{}) {
		return UnlimitedText
	}
	n, _ := v.(int64)
	return showSize(n)
}

func (sizeKind) Compare(_ *templates.Option, a, b Value) (int, bool) {
	ua, ub := a == (Unlimited{}), b == (Unlimited{})
	switch {
	case ua && ub:
		return 0, true
	case ua:
		return 1, true
	case ub:
		return -1, true
	}
	x, ok1 := a.(int64)
	y, ok2 := b.(int64)
	return cmpInt(x, y), ok1 && ok2
}

// ── duration ─────────────────────────────────────────────

type durationKind struct{}

func (durationKind) Name() string { return templates.TypeDuration }

// maxSeconds keeps seconds × 1e9 inside time.Duration.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// parseDuration reads "30d", "1h30m" or a number of seconds.
func parseDuration(raw any) (int64, error) {
	if isNumber(raw) {
		v, err := toInt(raw)
		if err != nil {
			return 0, err
		}
		if v < 0 || v > maxSeconds {
			return 0, fmt.Errorf("a duration is 0-%d seconds", maxSeconds)
		}
		return v, nil
	}
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("want a duration such as 30d or 90m, not %T", raw)
	}
	d, err := str2duration.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (e.g. 30d, 12h, 90m, 45s)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("a duration can't be negative")
	}
	if d%time.Second != 0 {
		return 0, fmt.Errorf("%q: durations are whole seconds", s)
	}
	return int64(d / time.Second), nil
}

// showDuration writes seconds as days, hours, minutes and seconds
// ("30d", "1h30m").
func showDuration(s int64) string {
	if s == 0 {
		return "0s"
	}
	var b strings.Builder
	for _, u := range []struct {
		n int64
		l string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}} {
		if s >= u.n {
			fmt.Fprintf(&b, "%d%s", s/u.n, u.l)
			s %= u.n
		}
	}
	return b.String()
}

func (durationKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "min", "max"); err != nil {
		return err
	}
	_, err := readBounds(o, parseDuration)
	return err
}

func (durationKind) Parse(o *templates.Option, raw any) (Value, error) {
	v, err := parseDuration(raw)
	if err != nil {
		return nil, err
	}
	b, err := readBounds(o, parseDuration)
	if err != nil {
		return nil, err
	}
	if err := b.check(v, showDuration); err != nil {
		return nil, err
	}
	return v, nil
}

func (durationKind) Display(_ *templates.Option, v Value) string {
	n, _ := v.(int64)
	return showDuration(n)
}

func (durationKind) Compare(_ *templates.Option, a, b Value) (int, bool) {
	x, ok1 := a.(int64)
	y, ok2 := b.(int64)
	return cmpInt(x, y), ok1 && ok2
}

// ── bool ─────────────────────────────────────────────────

type boolKind struct{}

func (boolKind) Name() string { return templates.TypeBool }

func (boolKind) CheckOption(o *templates.Option) error { return onlyFields(o) }

func (boolKind) Parse(_ *templates.Option, raw any) (Value, error) {
	b, ok := raw.(bool)
	if !ok {
		return nil, fmt.Errorf("want true or false, not %v", raw)
	}
	return b, nil
}

func (boolKind) Display(_ *templates.Option, v Value) string {
	if b, _ := v.(bool); b {
		return "Yes"
	}
	return "No"
}

func (boolKind) Compare(_ *templates.Option, a, b Value) (int, bool) {
	x, ok1 := a.(bool)
	y, ok2 := b.(bool)
	toI := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	return cmpInt(toI(x), toI(y)), ok1 && ok2
}

// ── enum ─────────────────────────────────────────────────

type enumKind struct{}

func (enumKind) Name() string { return templates.TypeEnum }

// checkChoices: at least one; values unique, non-empty, ≤ 128, no control
// characters; labels a single non-empty line ≤ 64.
func checkChoices(cs []templates.EnumOption) error {
	if len(cs) == 0 {
		return fmt.Errorf("options: at least one {value, label}")
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if c.Value == "" || len(c.Value) > 128 || checkText(c.Value) != nil {
			return fmt.Errorf("options: value %q must be 1-128 characters without control characters", c.Value)
		}
		if seen[c.Value] {
			return fmt.Errorf("options: value %q listed twice", c.Value)
		}
		seen[c.Value] = true
		if c.Label == "" || len(c.Label) > 64 || checkText(c.Label) != nil {
			return fmt.Errorf("options: value %q needs a single-line label of at most 64 characters", c.Value)
		}
	}
	return nil
}

// rank is v's 0-based position in cs (-1 = not a choice).
func rank(cs []templates.EnumOption, v any) int {
	s, ok := v.(string)
	if !ok {
		return -1
	}
	for i, c := range cs {
		if c.Value == s {
			return i
		}
	}
	return -1
}

func choiceValues(cs []templates.EnumOption) string {
	vs := make([]string, len(cs))
	for i, c := range cs {
		vs[i] = c.Value
	}
	return strings.Join(vs, ", ")
}

func parseChoice(cs []templates.EnumOption, raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("want one of %s, not %T", choiceValues(cs), raw)
	}
	if rank(cs, s) < 0 {
		return "", fmt.Errorf("%q is not one of %s", s, choiceValues(cs))
	}
	return s, nil
}

func (enumKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "options"); err != nil {
		return err
	}
	return checkChoices(o.Choices)
}

func (enumKind) Parse(o *templates.Option, raw any) (Value, error) {
	return parseChoice(o.Choices, raw)
}

func (enumKind) Display(o *templates.Option, v Value) string {
	if i := rank(o.Choices, v); i >= 0 {
		return o.Choices[i].Label
	}
	s, _ := v.(string)
	return s
}

func (enumKind) Compare(o *templates.Option, a, b Value) (int, bool) {
	x, y := rank(o.Choices, a), rank(o.Choices, b)
	if x < 0 || y < 0 {
		return 0, false
	}
	return cmpInt(int64(x), int64(y)), true
}
