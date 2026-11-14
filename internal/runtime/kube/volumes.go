package kube

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/portcullis/hub/internal/runtime"
)

// Compose's volume labels, as the Hub's backup code reads them.
const (
	composeProject = "com.docker.compose.project"
	composeVolume  = "com.docker.compose.volume"
)

// volume is a PVC as the runtime's Volume: the compose labels the Hub's
// backups and guarded delete compare (the project, the volume key).
func volume(p corev1.PersistentVolumeClaim) runtime.Volume {
	l := map[string]string{}
	for k, v := range p.Labels {
		l[k] = v
	}
	if inst := p.Labels[LabelInstance]; inst != "" {
		l[composeProject] = runtime.ProjectName(inst)
		l[composeVolume] = p.Labels[LabelVolume]
	}
	// A plain volume for the Hub's restore (driver local, no options);
	// its owner is the translation's (VolumeOwner).
	return runtime.Volume{Name: p.Name, Driver: "local", Labels: l}
}

// ListVolumes lists the instance's PVCs (zero Filter / All: every
// instance's).
func (b *Backend) ListVolumes(ctx context.Context, f runtime.Filter) ([]runtime.Volume, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	sel := LabelInstance
	if f.Instance != "" {
		sel = LabelInstance + "=" + f.Instance
	}
	l, err := b.cfg.Client.CoreV1().PersistentVolumeClaims(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	var out []runtime.Volume
	for _, p := range l.Items {
		out = append(out, volume(p))
	}
	return out, nil
}

// InspectVolume reads one PVC (IsNotFound when missing).
func (b *Backend) InspectVolume(ctx context.Context, name string) (runtime.Volume, error) {
	if err := b.gate(); err != nil {
		return runtime.Volume{}, err
	}
	p, err := b.cfg.Client.CoreV1().PersistentVolumeClaims(b.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return runtime.Volume{}, nf(err)
	}
	return volume(*p), nil
}

// CreateVolume creates a PVC from v: its instance from the compose
// project label, its key from the volume label, its owner from Options
// (portcullis.io/uid|gid|mode: the provisioner refuses a PVC without
// them, fail closed).
func (b *Backend) CreateVolume(ctx context.Context, v runtime.Volume) error {
	if err := b.gate(); err != nil {
		return err
	}
	inst, ok := strings.CutPrefix(v.Labels[composeProject], runtime.ProjectPrefix)
	key := v.Labels[composeVolume]
	if !ok || inst == "" || key == "" {
		return fmt.Errorf("volume %s: no instance or key", v.Name)
	}
	if v.Name != PVCName(inst, key) {
		return fmt.Errorf("volume %s is not instance %s's PVC for %s (%s)", v.Name, inst, key, PVCName(inst, key))
	}
	ann := map[string]string{}
	for _, k := range []string{AnnotationUID, AnnotationGID, AnnotationMode} {
		if val := v.Options[k]; val != "" {
			ann[k] = val
		}
	}
	if len(ann) != 3 {
		return fmt.Errorf("volume %s: its owner is unknown (deploy the instance once, or restore from a backup made on Kubernetes)", v.Name)
	}
	sc := StorageClassApps
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: b.cfg.Namespace,
		Labels: map[string]string{LabelInstance: inst, LabelVolume: sanitizeLabel(key)}, Annotations: ann},
		Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: &sc,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}}}}
	_, err := b.cfg.Client.CoreV1().PersistentVolumeClaims(b.cfg.Namespace).Create(ctx, pvc, metav1.CreateOptions{FieldManager: FieldManager})
	return err
}

// RemoveVolume deletes a PVC of an instance (the guarded delete, §11.4;
// a PVC without the instance label is never deleted).
func (b *Backend) RemoveVolume(ctx context.Context, name string) error {
	if err := b.gate(); err != nil {
		return err
	}
	p, err := b.cfg.Client.CoreV1().PersistentVolumeClaims(b.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nf(err)
	}
	if p.Labels[LabelInstance] == "" {
		return fmt.Errorf("pvc %s belongs to no instance: not deleting it", name)
	}
	pvcs := b.cfg.Client.CoreV1().PersistentVolumeClaims(b.cfg.Namespace)
	if err := pvcs.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return nf(err)
	}
	// Gone before it returns (pvc-protection finalizer): a restore
	// creates the same name next.
	deadline := b.cfg.Clock().Add(helperReady)
	for {
		if _, err := pvcs.Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		if !b.cfg.Clock().Before(deadline) {
			return fmt.Errorf("pvc %s is still being deleted after %s", name, helperReady)
		}
		if err := b.cfg.Sleep(ctx, b.cfg.Poll); err != nil {
			return err
		}
	}
}

// VolumeOwner is the owner annotations (portcullis.io/uid|gid|mode) the
// translation gives instance p's PVC of volume key (a restore creates
// the PVC before any deploy): the plan translated without resolving
// images.
func (b *Backend) VolumeOwner(ctx context.Context, p runtime.Project, key string) (map[string]string, error) {
	if p.Model == nil {
		return nil, fmt.Errorf("%s: the project's model isn't loaded", p.Instance)
	}
	in := Input{Instance: p.Instance, Namespace: b.cfg.Namespace, Model: p.Model, HubImage: b.cfg.HubImage, BindRoots: b.cfg.BindRoots, Settings: b.cfg.Settings, Digests: map[string]string{}}
	if x := p.Inputs; x != nil {
		in.Template, in.TemplateFiles, in.PersonSecrets, in.Jobs = x.Template, x.TemplateFiles, x.PersonSecrets, x.Jobs
	}
	for _, s := range p.Model.Services {
		in.Digests[s.Image] = s.Image
	}
	pl, err := Translate(in)
	if err != nil {
		return nil, err
	}
	want := PVCName(p.Instance, key)
	for _, o := range pl.Objects() {
		if o.GetKind() == "PersistentVolumeClaim" && o.GetName() == want {
			return o.GetAnnotations(), nil
		}
	}
	return nil, fmt.Errorf("%s has no volume %s", p.Instance, key)
}

// notFoundError is a missing object as the Hub's callers test it
// (containerd errdefs' NotFound() interface, docker.IsNotFound).
type notFoundError struct{ err error }

func (e notFoundError) Error() string { return e.err.Error() }
func (e notFoundError) Unwrap() error { return e.err }
func (notFoundError) NotFound()       {}

// nf marks a Kubernetes NotFound as the runtime's not-found.
func nf(err error) error {
	if apierrors.IsNotFound(err) {
		return notFoundError{err}
	}
	return err
}
