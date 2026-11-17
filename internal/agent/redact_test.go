package agent

import (
	"strconv"
	"strings"
	"testing"
)

// TestRedactEnvForms (final re-review N7): an env value is redacted in
// every form an error may quote it — as compose reads it and as written,
// quoted, escaped, with an inline comment, exported, Go-quoted.
func TestRedactEnvForms(t *testing.T) {
	env := "A=plainSecret1\n" +
		"B=\"dq\\\"Secret2\"\n" +
		"C='sqSecret3'\n" +
		"D=rawSecret4 # a comment\n" +
		"export E=exportedSecret5\n" +
		"F=\"tab\\tSecret6\"\n"
	for _, leak := range []string{"plainSecret1", `dq"Secret2`, `dq\"Secret2`, "sqSecret3", "rawSecret4", "rawSecret4 # a comment", "exportedSecret5",
		"tab\tSecret6", strconv.Quote("tab\tSecret6")} {
		msg := redactEnvValues("compose: bad value "+leak+" in service", []byte(env))
		for _, part := range []string{"Secret1", "Secret2", "Secret3", "Secret4", "Secret5", "Secret6"} {
			if strings.Contains(msg, part) {
				t.Errorf("%q: %s", leak, msg)
			}
		}
	}
}
