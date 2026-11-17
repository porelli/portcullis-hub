package host

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// sudoersCheck is the candidate file visudo -cf checks first.
const sudoersCheck = "/etc/portcullis/sudoers.check"

// SudoersBody is /etc/sudoers.d/portcullis: one line per account.
func SudoersBody(accounts []string) []byte {
	if len(accounts) == 0 {
		return nil
	}
	s := append([]string(nil), accounts...)
	sort.Strings(s)
	var b strings.Builder
	b.WriteString("# Written by portcullis host sync. Do not edit.\n")
	for _, a := range s {
		b.WriteString(a + " ALL=(ALL:ALL) NOPASSWD: ALL\n")
	}
	return []byte(b.String())
}

// CheckSudoers runs visudo -cf on the candidate (the live file is
// replaced only after this passes).
func CheckSudoers(ctx context.Context, sys System, body []byte) error {
	if err := sys.WriteFileAtomic(sudoersCheck, body, 0o440); err != nil {
		return err
	}
	defer sys.Remove(sudoersCheck)
	if out, err := sys.Run(ctx, "visudo", "-cf", sudoersCheck); err != nil {
		return fmt.Errorf("visudo refused the sudoers file: %s", firstLine(out))
	}
	return nil
}

// NarrowSudoers rewrites /etc/sudoers.d/portcullis keeping only the
// accounts keep accepts (never adding one): before the per-account sudo
// checks (only sudo a privileged grant still gives stays in the way) and
// after a failed apply's rollback (RR-M2: a rollback never brings back a
// rule the new bundle removed). Nothing left, or a candidate visudo
// refuses: the file goes (fail closed).
func NarrowSudoers(ctx context.Context, sys System, keep func(name string) bool) error {
	cur, err := readMaybe(sys, SudoersFile)
	if err != nil || cur == nil {
		return err
	}
	var have, kept []string
	for _, l := range strings.Split(string(cur), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		have = append(have, f[0])
		if keep(f[0]) {
			kept = append(kept, f[0])
		}
	}
	if len(kept) == len(have) {
		return nil
	}
	body := SudoersBody(kept)
	if body == nil || CheckSudoers(ctx, sys, body) != nil {
		return sys.Remove(SudoersFile)
	}
	return sys.WriteFileAtomic(SudoersFile, body, fsMode(0o440))
}
