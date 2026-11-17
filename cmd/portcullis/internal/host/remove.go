package host

import (
	"context"
	"fmt"
	"time"
)

// RemoveTrust deletes exactly the files the tools wrote, locks the
// Portcullis accounts (deleteAccounts: deletes them, homes kept), reloads
// sshd and stops the services (contract §18.8 "Removing a host").
//
// fromAgent (FR-H3): the host sync agent removing itself after the Hub
// said "removed". Trust goes first — accounts locked, the CA, principals,
// drop-in and sudoers removed, sshd reloaded — and its own unit is
// disabled and stopped LAST (systemctl stop --no-block: the stop may
// SIGTERM this very process, but only after everything is gone). A manual
// `host remove` stops the agent first, so it can't rewrite the files
// meanwhile.
func RemoveTrust(ctx context.Context, sys System, deleteAccounts, serviceNone, fromAgent bool) error {
	if !fromAgent {
		stopService(ctx, sys, false)
	}
	acc, err := loadAccounts(sys)
	if err == nil {
		for name := range acc.users {
			if !acc.ours(name) {
				continue
			}
			if deleteAccounts {
				_ = removeAccount(ctx, sys, acc, name, time.Now())
			} else {
				_ = lock(ctx, sys, name)
			}
		}
	}
	tx := NewTransaction(sys)
	ps, _ := sys.Glob(PrincipalsDir + "/*")
	files := append([]string{DropInFile, SudoersFile, HostCertFile, UserCAFile}, ps...)
	files = append(files, SyncUnit, SyncPlist, revokedService, revokedTimer, revokedPlist, revokedDomain, AgentFile, StateFile, CeilingFile, BundleFile)
	for _, f := range files {
		if err := tx.StageRemove(f); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(func() error {
		if err := SSHDTest(ctx, sys); err != nil {
			return err
		}
		return Reload(ctx, sys, serviceNone)
	}); err != nil {
		if fromAgent {
			return fmt.Errorf("removing the Portcullis files would break sshd: %v (the files are kept, the Portcullis accounts are locked; fix sshd and run portcullis host remove)", err)
		}
		return fmt.Errorf("removing the Portcullis files would break sshd: %v (the files are kept, the Portcullis accounts are locked and the sync service is stopped; fix sshd and run portcullis host remove again)", err)
	}
	// The revoked-keys file goes last, after sshd stopped reading it.
	_ = sys.Remove(RevokedKeysFile)
	if fromAgent {
		stopService(ctx, sys, true)
	}
	if exists(sys, "/run/systemd/system") {
		_, _ = sys.Run(ctx, "systemctl", "daemon-reload")
	}
	return nil
}
