package kube

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FrontdoorStatusObject / FrontdoorStatusKey are the front door's status
// document (contract §20.8): the ConfigMap frontdoor-status in the core
// namespace, key status.json, written only by the front door's own Role.
// The Hub's core Role has get on it, nothing more.
const (
	FrontdoorStatusObject = "frontdoor-status"
	FrontdoorStatusKey    = "status.json"
)

// frontdoorStatusMax bounds the document the Hub takes (a ConfigMap holds
// at most 1 MiB).
const frontdoorStatusMax = 1 << 20

// FrontdoorStatus reads frontdoor-status' status.json (a GET: the write
// fence lets it through while this Hub stands by). The HA page's front
// door state and worst-case texts come from it; the Hub never reads the
// front door's credentials (frontdoor-env).
func (b *Backend) FrontdoorStatus(ctx context.Context) ([]byte, error) {
	cm, err := b.cfg.Client.CoreV1().ConfigMaps(b.cfg.CoreNamespace).Get(ctx, FrontdoorStatusObject, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	v, ok := cm.Data[FrontdoorStatusKey]
	if !ok {
		return nil, fmt.Errorf("%s holds no %s", FrontdoorStatusObject, FrontdoorStatusKey)
	}
	if len(v) > frontdoorStatusMax {
		return nil, fmt.Errorf("%s's %s is over 1 MiB", FrontdoorStatusObject, FrontdoorStatusKey)
	}
	return []byte(v), nil
}
