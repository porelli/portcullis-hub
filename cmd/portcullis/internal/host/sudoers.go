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
