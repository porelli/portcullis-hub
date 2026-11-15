package kube

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// RegistryResolver resolves image references with an anonymous HEAD on
// the registry (go-containerregistry). Only fully qualified references
// (registry host first) are accepted: no implicit docker.io.
type RegistryResolver struct{}

// Resolve answers name@sha256:… for ref (a ref already pinned by digest
// is checked and returned as written).
func (RegistryResolver) Resolve(ctx context.Context, ref string) (string, error) {
	if !qualified(ref) {
		return "", fmt.Errorf("image %s is not fully qualified (registry host first)", ref)
	}
	r, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return "", fmt.Errorf("image %s: %w", ref, err)
	}
	if d, ok := r.(name.Digest); ok {
		return d.Context().Name() + "@" + d.DigestStr(), nil
	}
	desc, err := remote.Head(r, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return "", fmt.Errorf("image %s: %w", ref, err)
	}
	return r.Context().Name() + "@" + desc.Digest.String(), nil
}

// qualified: the first path component is a registry host (has a dot or
// a port, or is localhost).
func qualified(ref string) bool {
	host, _, ok := strings.Cut(ref, "/")
	return ok && (strings.ContainsAny(host, ".:") || host == "localhost")
}
