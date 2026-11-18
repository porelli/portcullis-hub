package host

import (
	"context"
	"errors"
	"fmt"
)

// The managed host's agent service (plan C24).
const (
	SyncUnit  = "/etc/systemd/system/portcullis-host-sync.service"
	SyncPlist = "/Library/LaunchDaemons/eu.portcullis.host-sync.plist"
)

// SyncUnitBody is the systemd unit, hardened as far as useradd allows:
// shadow-utils rewrites /etc/passwd, /etc/group and /etc/shadow through
// lock and temporary files in /etc and a rename, so /etc must stay
// writable (ProtectSystem=true: /usr and /boot read-only) — spec §8.9's
// ProtectSystem=strict with per-file write paths would break every
// account change.
func SyncUnitBody(self string) []byte {
	return []byte(`# Written by portcullis host enroll. Do not edit.
[Unit]
Description=Portcullis: keep this host's SSH access current
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + systemdQuote(self) + ` host sync
Restart=always
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`)
}

// SyncPlistBody is the launchd daemon.
func SyncPlistBody(self string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>eu.portcullis.host-sync</string>
<key>ProgramArguments</key><array><string>` + xmlEscape(self) + `</string><string>host</string><string>sync</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
`)
}

// ErrNoServiceManager: neither systemd nor launchd (C12).
var ErrNoServiceManager = errors.New("no systemd or launchd here: run with --service none and start `portcullis host sync` yourself (e.g. under your init system)")

// serviceKind is auto's pick ("" = none possible).
func serviceKind(sys System) string {
	if sys.GOOS() == "darwin" {
		return "launchd"
	}
	if sys.LookPath("systemctl") != "" && exists(sys, "/run/systemd/system") {
		return "systemd"
	}
	return ""
}

// stageService writes the unit for kind (after the binary check).
func stageService(tx *Transaction, sys System, kind, self string) error {
	real, err := CheckRootExecutable(sys, self)
	if err != nil {
		return err
	}
	switch kind {
	case "systemd":
		if err := sys.MkdirAll("/etc/systemd/system", 0o755); err != nil {
			return err
		}
		return tx.Stage(SyncUnit, SyncUnitBody(real), 0o644)
	case "launchd":
		return tx.Stage(SyncPlist, SyncPlistBody(real), 0o644)
	}
	return ErrNoServiceManager
}

func startService(ctx context.Context, sys System, kind string) error {
	switch kind {
	case "systemd":
		if _, err := sys.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if out, err := sys.Run(ctx, "systemctl", "enable", "--now", "portcullis-host-sync.service"); err != nil {
			return fmt.Errorf("systemctl enable: %s", firstLine(out))
		}
	case "launchd":
		if out, err := sys.Run(ctx, "launchctl", "bootstrap", "system", SyncPlist); err != nil {
			return fmt.Errorf("launchctl bootstrap: %s", firstLine(out))
		}
	}
	return nil
}

// stopService disables and stops the agent's services. self: the sync
// agent stopping its own unit after removing everything (FR-H3) — the
// unit files may already be gone, so it doesn't look for them, and the
// stop is queued (--no-block) so systemd's SIGTERM comes after the work.
func stopService(ctx context.Context, sys System, self bool) {
	if self {
		if exists(sys, "/run/systemd/system") {
			_, _ = sys.Run(ctx, "systemctl", "disable", "portcullis-host-sync.service")
			_, _ = sys.Run(ctx, "systemctl", "stop", "--no-block", "portcullis-host-sync.service")
		}
		if exists(sys, "/Library/LaunchDaemons") {
			_, _ = sys.Run(ctx, "launchctl", "bootout", "system/eu.portcullis.host-sync")
		}
	} else {
		if exists(sys, SyncUnit) {
			_, _ = sys.Run(ctx, "systemctl", "disable", "--now", "portcullis-host-sync.service")
		}
		if exists(sys, SyncPlist) {
			_, _ = sys.Run(ctx, "launchctl", "bootout", "system/eu.portcullis.host-sync")
		}
	}
	if exists(sys, revokedTimer) {
		_, _ = sys.Run(ctx, "systemctl", "disable", "--now", "portcullis-revoked-keys.timer")
	}
	if exists(sys, revokedPlist) {
		_, _ = sys.Run(ctx, "launchctl", "bootout", "system/eu.portcullis.revoked-keys")
	}
}
