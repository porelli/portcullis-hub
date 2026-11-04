package settings

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/portcullis/hub/internal/templates"
)

// The file-sharing kinds (contract §13.2, §13.16; preflight F4): ordinary
// built-in kinds whose values only the Hub computes. No admin input is
// ever a value of either (the settings panel and PUT …/settings never
// address them); their structural rules are templates.ValidateSettingsSpec's.

// errSetByTheHub refuses any admin input for these kinds.
var errSetByTheHub = errors.New("set by the Hub (one value per person): not an admin setting")

// personSecretKind is a per-person file-share password; only its status
// is ever shown.
type personSecretKind struct{}

func (personSecretKind) Name() string { return templates.TypePersonSecret }

func (personSecretKind) CheckOption(o *templates.Option) error { return onlyFields(o) }

func (personSecretKind) Parse(*templates.Option, any) (Value, error) { return nil, errSetByTheHub }

// Display shows a status string as it is (never a password or hash: the
// Hub has neither as a value).
func (personSecretKind) Display(_ *templates.Option, v Value) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (personSecretKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// personIDKind is a per-person number the Hub allocates from a pool.
type personIDKind struct{}

func (personIDKind) Name() string { return templates.TypePersonID }

func (personIDKind) CheckOption(o *templates.Option) error { return onlyFields(o) }

func (personIDKind) Parse(*templates.Option, any) (Value, error) { return nil, errSetByTheHub }

// Display is the number.
func (personIDKind) Display(_ *templates.Option, v Value) string {
	switch n := v.(type) {
	case int64:
		return strconv.FormatInt(n, 10)
	case int:
		return strconv.Itoa(n)
	}
	return fmt.Sprint(v)
}

func (personIDKind) Compare(_ *templates.Option, a, b Value) (int, bool) {
	x, ok1 := a.(int64)
	y, ok2 := b.(int64)
	if !ok1 || !ok2 {
		return 0, false
	}
	switch {
	case x < y:
		return -1, true
	case x > y:
		return 1, true
	}
	return 0, true
}
