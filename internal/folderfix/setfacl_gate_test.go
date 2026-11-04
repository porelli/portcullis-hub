package folderfix

import (
	"fmt"
	"os"
	"testing"
)

// setfaclUnavailable ends a test whose kernel cross-check can't run: a skip
// on a developer machine, a failure in CI (CI set), where the acl package is
// installed and the check must not pass silently.
func setfaclUnavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
		return
	}
	t.Skipf(format, args...)
}

// recordTB records how setfaclUnavailable ended the test.
type recordTB struct {
	testing.TB
	fatal, skip string
}

func (r *recordTB) Helper()                   {}
func (r *recordTB) Fatalf(f string, a ...any) { r.fatal = fmt.Sprintf(f, a...) }
func (r *recordTB) Skipf(f string, a ...any)  { r.skip = fmt.Sprintf(f, a...) }

func TestSetfaclUnavailableFatalInCI(t *testing.T) {
	t.Setenv("CI", "true")
	r := &recordTB{}
	setfaclUnavailable(r, "setfacl: %s", "no ACL support")
	if r.fatal == "" || r.skip != "" {
		t.Fatalf("with CI set: fatal %q skip %q, want fatal", r.fatal, r.skip)
	}

	t.Setenv("CI", "")
	r = &recordTB{}
	setfaclUnavailable(r, "setfacl: %s", "no ACL support")
	if r.skip == "" || r.fatal != "" {
		t.Fatalf("without CI: fatal %q skip %q, want skip", r.fatal, r.skip)
	}
}
