package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Labels and annotations the translator sets (and only the translator:
// compose labels become the annotation ComposeLabels, never pod labels).
const (
	LabelInstance  = "portcullis.io/instance"
	LabelService   = "portcullis.io/service"
	LabelNetPrefix = "portcullis.io/net-"
	LabelEgress    = "portcullis.io/egress"
	LabelHelper    = "portcullis.io/helper"
	LabelVolume    = "portcullis.io/volume"
	LabelVPNSlot   = "portcullis.io/vpn-slot"
	LabelComponent = "portcullis.io/component"
	// LabelOwner marks the edge namespace's objects: hub (the Hub's
	// routes) or core (the chart's, never touched by the Hub).
	LabelOwner = "portcullis.io/owner"
	OwnerHub   = "hub"
	// EdgeNamespace is the default edge namespace (Traefik watches only
	// it: IngressRoutes and Middlewares).
	EdgeNamespace = "portcullis-edge"
	LabelProbe    = "portcullis.io/probe"
	// ProbeInstance is the probe pods' instance label value (no
	// instance id starts with portcullis, §11.1).
	ProbeInstance = "portcullis-probe"
	// AnnotationComposeLabels holds the pod's compose labels per
	// container, AnnotationServices each container's compose service
	// (JSON objects on the pod template).
	AnnotationComposeLabels = "portcullis.io/compose-labels"
	AnnotationServices      = "portcullis.io/services"
	// AnnotationRev is a delivery's revision on the pod template.
	AnnotationRev = "portcullis.io/rev"
	// PVC ownership annotations (the provisioner's patterns, K3).
	AnnotationUID  = "portcullis.io/uid"
	AnnotationGID  = "portcullis.io/gid"
	AnnotationMode = "portcullis.io/mode"
	// FieldManager is the Hub's server-side apply field manager.
	FieldManager = "portcullis-hub"
	// StorageClassApps is the StorageClass of app PVCs.
	StorageClassApps = "portcullis-apps"
)

// maxName is the longest object name the translator gives (a DNS label).
const maxName = 63

// sanitize lowercases s and maps "_" and "." to "-".
func sanitize(s string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(s))
}

// ObjectName is the name of the objects of compose service service of
// instance (contract §11.2): "<instance>--<service>", lowercase, "_" and
// "." → "-"; past 63 characters truncated plus "-<hash8>" (the first 8
// hex digits of the sha256 of the original pair).
func ObjectName(instance, service string) string {
	return joinName(instance, service, "")
}

// joinName is "<instance>--<part><suffix>" under the 63-character rule
// (suffix is kept whole: "-pw", "-secrets", …).
func joinName(instance, part, suffix string) string {
	n := sanitize(instance) + "--" + sanitize(part) + suffix
	if len(n) <= maxName {
		return n
	}
	sum := sha256.Sum256([]byte(instance + "\x00" + part + "\x00" + suffix))
	h := "-" + hex.EncodeToString(sum[:])[:8]
	keep := maxName - len(h) - len(suffix)
	base := strings.TrimRight((sanitize(instance) + "--" + sanitize(part))[:keep], "-")
	return base + h + suffix
}

// PVCName is the PVC of named volume key of instance.
func PVCName(instance, key string) string { return joinName(instance, key, "") }

// EnvSecretName is the instance's env Secret.
func EnvSecretName(instance string) string { return joinName(instance, "env", "") }

// PersonSecretName is the per-person secrets Secret of option key.
func PersonSecretName(instance, key string) string { return joinName(instance, key, "-pw") }

// DataFileName / DataSecretsName are a data file's ConfigMap and its
// secrets file's Secret (§13.7).
func DataFileName(instance, name string) string    { return joinName(instance, name, "") }
func DataSecretsName(instance, name string) string { return joinName(instance, name, "-secrets") }

// TemplateFilesName is the ConfigMap of template's files with content
// hash sum (hex).
func TemplateFilesName(template, sum string) string {
	n := "tpl-" + sanitize(template) + "-" + sum[:10]
	if len(n) > maxName {
		n = "tpl-" + sanitize(template)[:maxName-15] + "-" + sum[:10]
	}
	return n
}
