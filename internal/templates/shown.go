package templates

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Refusal texts reach the catalog, logs, the doctor and the API: they
// name services, routers, label keys and numbers, never a value the
// instance's settings or env could have put in (a secret, an admin's
// path). The Shown* filters let a value through only in a shape that
// can't carry one, else a placeholder.

// linuxCaps are the capability names (without CAP_).
var linuxCaps = []string{"AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE", "BLOCK_SUSPEND", "BPF", "CHECKPOINT_RESTORE", "CHOWN",
	"DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "IPC_LOCK", "IPC_OWNER", "KILL", "LEASE", "LINUX_IMMUTABLE",
	"MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW", "PERFMON", "SETFCAP",
	"SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE",
	"SYS_RAWIO", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "SYSLOG", "WAKE_ALARM", "ALL"}

// ShownCap is c when it is a capability name, else "a capability".
func ShownCap(c string) string {
	if c = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_"); slices.Contains(linuxCaps, c) {
		return c
	}
	return "a capability"
}

// ShownIP is ip when it is an IP address, else "an address".
func ShownIP(ip string) string {
	if a, err := netip.ParseAddr(strings.Trim(ip, "[]")); err == nil {
		return a.String()
	}
	return "an address"
}

var shownNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.@-]{0,62}$`)

// ShownName is a Traefik reference (service, middleware) when it has a
// name's shape, else "a name".
func ShownName(s string) string {
	if shownNameRe.MatchString(s) {
		return s
	}
	return "a name"
}

// ShownVolumeType is a compose volume type when it is one, else
// "an unknown".
func ShownVolumeType(t string) string {
	if slices.Contains([]string{"bind", "volume", "tmpfs", "npipe", "cluster", "image"}, t) {
		return t
	}
	return "an unknown"
}
