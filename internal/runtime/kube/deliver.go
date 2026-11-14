package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"

	"github.com/portcullis/hub/internal/runtime"
)

var mergePatch = ktypes.MergePatchType

// ErrRevNotMounted: the delivery's revision never showed up in the
// mounted copy (nor in the restarted pod): the delivery isn't recorded.
var ErrRevNotMounted = errors.New("the delivered revision isn't mounted")

// DeliveryObject is a ConfigMap or Secret delivery into a running
// instance: the object, its files, where its service mounts it.
type DeliveryObject struct {
	// Kind is ConfigMap or Secret; Name the object's name.
	Kind, Name string
	// Data are the object's keys (.rev is added).
	Data map[string][]byte
	// Service is the compose service mounting it at Mount.
	Service, Mount string
}

// Deliver updates obj with key .rev = rev and returns only once the
// mounted copy in the service's running pod carries rev (polled with
// /portcullis-bin/hub rev <mount> every Poll, up to DeliverWait, the
// kubelet's own sync); when it doesn't, the service is restarted through
// its Deployment's pod template (annotation portcullis.io/rev) and rev
// counts once the new pod is Ready and mounts it. The caller records rev
// only on a nil error.
func (b *Backend) Deliver(ctx context.Context, instance string, obj DeliveryObject, rev string) error {
	if err := b.gate(); err != nil {
		return err
	}
	if rev == "" || strings.ContainsAny(rev, "\n\r") {
		return fmt.Errorf("delivery %s: bad revision", obj.Name)
	}
	if err := b.updateObject(ctx, instance, obj, rev); err != nil {
		return err
	}
	deadline := b.cfg.Clock().Add(b.cfg.DeliverWait)
	for first := true; ; first = false {
		ok, seen, err := b.mountedRev(ctx, instance, obj, rev)
		if err != nil {
			return err
		}
		if ok || first && !seen {
			// Matched, or nothing of the service runs: the next start
			// mounts the new object.
			return nil
		}
		if !b.cfg.Clock().Before(deadline) {
			break
		}
		if err := b.cfg.Sleep(ctx, b.cfg.Poll); err != nil {
			return err
		}
	}
	// Not synced within the wait: restart through the Deployment.
	name := ObjectName(instance, obj.Service)
	if err := b.restartDeployment(ctx, instance, name, rev); err != nil {
		return fmt.Errorf("delivery %s: the mounted copy didn't update within %s, and restarting %s failed: %w", obj.Name, b.cfg.DeliverWait, obj.Service, err)
	}
	ready := b.cfg.Clock().Add(b.cfg.ReadyWait)
	for {
		ok, _, err := b.mountedRev(ctx, instance, obj, rev)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !b.cfg.Clock().Before(ready) {
			return fmt.Errorf("delivery %s: %w after restarting %s", obj.Name, ErrRevNotMounted, obj.Service)
		}
		if err := b.cfg.Sleep(ctx, b.cfg.Poll); err != nil {
			return err
		}
	}
}

// updateObject writes obj's data plus .rev (only the instance's own
// object: an existing one without its label is refused).
func (b *Backend) updateObject(ctx context.Context, instance string, obj DeliveryObject, rev string) error {
	data := map[string][]byte{}
	for k, v := range obj.Data {
		data[k] = v
	}
	data[".rev"] = []byte(rev)
	size := 0
	for k, v := range data {
		size += len(k) + len(v)
	}
	if size > MaxObject-16<<10 {
		return fmt.Errorf("%s %s exceeds 1 MiB: not delivered", strings.ToLower(obj.Kind), obj.Name)
	}
	labels := map[string]string{LabelInstance: instance}
	core := b.cfg.Client.CoreV1()
	switch obj.Kind {
	case "Secret":
		cur, err := core.Secrets(b.cfg.Namespace).Get(ctx, obj.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = core.Secrets(b.cfg.Namespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: obj.Name, Namespace: b.cfg.Namespace, Labels: labels}, Type: corev1.SecretTypeOpaque, Data: data}, metav1.CreateOptions{FieldManager: FieldManager})
			return err
		}
		if err != nil {
			return err
		}
		if cur.Labels[LabelInstance] != instance {
			return fmt.Errorf("secret %s isn't instance %s's: not touching it", obj.Name, instance)
		}
		cur.Data = data
		_, err = core.Secrets(b.cfg.Namespace).Update(ctx, cur, metav1.UpdateOptions{FieldManager: FieldManager})
		return err
	case "ConfigMap":
		cur, err := core.ConfigMaps(b.cfg.Namespace).Get(ctx, obj.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = core.ConfigMaps(b.cfg.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: obj.Name, Namespace: b.cfg.Namespace, Labels: labels}, BinaryData: data}, metav1.CreateOptions{FieldManager: FieldManager})
			return err
		}
		if err != nil {
			return err
		}
		if cur.Labels[LabelInstance] != instance {
			return fmt.Errorf("configmap %s isn't instance %s's: not touching it", obj.Name, instance)
		}
		cur.Data, cur.BinaryData = nil, data
		_, err = core.ConfigMaps(b.cfg.Namespace).Update(ctx, cur, metav1.UpdateOptions{FieldManager: FieldManager})
		return err
	}
	return fmt.Errorf("delivery %s: kind %s", obj.Name, obj.Kind)
}

// mountedRev: every running container of the service shows rev at the
// mount (seen: one runs).
func (b *Backend) mountedRev(ctx context.Context, instance string, obj DeliveryObject, rev string) (ok, seen bool, err error) {
	units, err := b.List(ctx, runtime.Filter{Instance: instance, Service: obj.Service})
	if err != nil {
		return false, false, err
	}
	seen = false
	for _, u := range units {
		if u.State != "running" {
			continue
		}
		seen = true
		var out bytes.Buffer
		code, _, err := b.exec(ctx, u.ID, runtime.ExecInput{Cmd: []string{"/portcullis-bin/hub", "rev", obj.Mount}, Timeout: 10 * time.Second, NoStdin: true}, &out, &bytes.Buffer{})
		if err != nil || code != 0 || strings.TrimSpace(out.String()) != rev {
			return false, true, nil
		}
	}
	return seen, seen, nil
}

// DeliverFile delivers a data file into a running instance: its secrets
// file's Secret first, then the data file's ConfigMap with .rev (one
// projected volume: the kubelet updates both together), then the mounted
// .rev waited for (Deliver).
func (b *Backend) DeliverFile(ctx context.Context, instance string, f runtime.FileDelivery) error {
	if err := b.gate(); err != nil {
		return err
	}
	fn := f.FileName
	if fn == "" {
		fn = f.Name + ".json"
	}
	if f.Secrets != nil {
		if err := b.updateObject(ctx, instance, DeliveryObject{Kind: "Secret", Name: DataSecretsName(instance, f.Name), Data: map[string][]byte{f.Name + ".secrets.json": f.Secrets}}, f.Rev); err != nil {
			return err
		}
	}
	return b.Deliver(ctx, instance, DeliveryObject{Kind: "ConfigMap", Name: DataFileName(instance, f.Name), Data: map[string][]byte{fn: f.Data}, Service: f.Service, Mount: f.Mount}, f.Rev)
}

// DeliverPersonSecret delivers a person_secret option's hash files as
// its *-pw Secret (at most 1 MiB), then waits for the mounted .rev.
func (b *Backend) DeliverPersonSecret(ctx context.Context, instance string, s runtime.SecretDelivery) error {
	if err := b.gate(); err != nil {
		return err
	}
	data := map[string][]byte{}
	for k, v := range s.Files {
		data[sanitizeKey(k)] = v
	}
	return b.Deliver(ctx, instance, DeliveryObject{Kind: "Secret", Name: PersonSecretName(instance, s.Key), Data: data, Service: s.Service, Mount: s.Mount}, s.Rev)
}
