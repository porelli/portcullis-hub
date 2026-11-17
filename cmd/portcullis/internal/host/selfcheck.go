package host

import (
	"encoding/xml"
	"fmt"
	"path"
	"strings"
)

// CheckRootExecutable refuses a binary a root service would run unless
// its resolved path and every parent directory are owned by root and
// writable by nobody else (no group or world write): otherwise a local
// user could swap it and run code as root. Answers the resolved path.
func CheckRootExecutable(sys System, p string) (string, error) {
	if p == "" || !path.IsAbs(p) {
		return "", fmt.Errorf("the portcullis binary's path %q isn't absolute", p)
	}
	real, err := sys.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %v", p, err)
	}
	for q := real; ; q = path.Dir(q) {
		uid, mode, err := sys.Owner(q)
		if err != nil {
			return "", fmt.Errorf("checking %s: %v", q, err)
		}
		if uid != 0 || mode.Perm()&0o022 != 0 {
			return "", fmt.Errorf("%s isn't owned by root and writable only by root, so a root service must not run %s: install portcullis as root, e.g. sudo install -o root -g root -m 0755 portcullis /usr/local/bin/portcullis, and run it from there", q, real)
		}
		if q == "/" {
			break
		}
	}
	return real, nil
}

// systemdQuote quotes an ExecStart word (systemd.syntax: double quotes,
// backslash escapes, % doubled for specifiers).
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// xmlEscape escapes a plist string.
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
