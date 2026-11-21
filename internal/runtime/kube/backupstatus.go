package kube

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackupStatusObject / BackupStatusKey are the last core backup that
// reached the backup destination (core plan Task 26): the ConfigMap
// portcullis-backup-status in the core namespace, key last_success (RFC
// 3339, UTC), written by ./portcullis backup --offsite. The Hub's core Role
// has get on it by name, nothing more; it holds no secret.
const (
	BackupStatusObject = "portcullis-backup-status"
	BackupStatusKey    = "last_success"
)

// LastCoreBackup is the doctor's backup_stale input (contract §14.5): the
// time of the last successful core backup to the destination, nil when
// none was ever recorded (the ConfigMap doesn't exist). An unreadable or
// malformed record is an error (the doctor names it), never "none".
func (b *Backend) LastCoreBackup(ctx context.Context) (*time.Time, error) {
	cm, err := b.cfg.Client.CoreV1().ConfigMaps(b.cfg.CoreNamespace).Get(ctx, BackupStatusObject, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, ok := cm.Data[BackupStatusKey]
	if !ok {
		return nil, fmt.Errorf("%s holds no %s", BackupStatusObject, BackupStatusKey)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, fmt.Errorf("%s's %s isn't an RFC 3339 time", BackupStatusObject, BackupStatusKey)
	}
	t = t.UTC()
	return &t, nil
}
