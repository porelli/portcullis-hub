package host

import (
	"context"
	"fmt"
	"time"
)

// RemoveTrust deletes exactly the files the tools wrote, locks the
// Portcullis accounts (deleteAccounts: deletes them, homes kept), stops
// the services and reloads sshd (contract §18.8 "Removing a host").
func RemoveTrust(ctx context.Context, sys System, deleteAccounts, serviceNone bool) error {
	stopService(ctx, sys)
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
		return fmt.Errorf("removing the Portcullis files would break sshd: %v (nothing was removed)", err)
	}
	// The revoked-keys file goes last, after sshd stopped reading it.
	_ = sys.Remove(RevokedKeysFile)
	if exists(sys, "/run/systemd/system") {
		_, _ = sys.Run(ctx, "systemctl", "daemon-reload")
	}
	return nil
}
