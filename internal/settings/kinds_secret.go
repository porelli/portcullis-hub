package settings

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/templates"
)

// secretKind is a write-only value (§13.2 secret). Values are delivered
// single-quoted in the env, so `'` is refused, exactly as the generated
// charsets never contain it (ascii_printable excludes it).
type secretKind struct{}

func (secretKind) Name() string { return templates.TypeSecret }

// maxSecretLen bounds a secret value (bytes).
const maxSecretLen = 4096

// SecretShown is what Display returns for any secret.
const SecretShown = "[set]"

func (secretKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "min_len", "max_len"); err != nil {
		return err
	}
	if o.Default != nil {
		return fmt.Errorf("a secret takes no default (set it, or declare generate)")
	}
	return checkLens(o.MinLen, o.MaxLen)
}

func (secretKind) Parse(o *templates.Option, raw any) (Value, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("want a string")
	}
	switch {
	case s == "":
		return nil, fmt.Errorf("a secret can't be empty (clear it instead)")
	case len(s) > maxSecretLen:
		return nil, fmt.Errorf("a secret is at most %d bytes", maxSecretLen)
	case strings.Contains(s, "'"):
		return nil, fmt.Errorf("a secret can't contain ' (env values are single-quoted)")
	}
	// Never echo the value in errors.
	if err := checkText(s); err != nil {
		return nil, fmt.Errorf("the secret %v", err)
	}
	n := utf8.RuneCountInString(s)
	if o.MinLen != nil && n < *o.MinLen {
		return nil, fmt.Errorf("must be at least %d characters", *o.MinLen)
	}
	if o.MaxLen != nil && n > *o.MaxLen {
		return nil, fmt.Errorf("must be at most %d characters", *o.MaxLen)
	}
	return s, nil
}

func (secretKind) Display(*templates.Option, Value) string { return SecretShown }

func (secretKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }
