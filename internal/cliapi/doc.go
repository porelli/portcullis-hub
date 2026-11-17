// Package cliapi holds the wire types, grammars and canonical messages
// shared by the Hub's CLI listener (internal/httpapi, internal/hub), the
// Portcullis CLI (cmd/portcullis) and the host agent (contract §18).
//
// It is the only Hub package the CLI may import (cmd/portcullis/deps_test.go),
// so it depends on the standard library and golang.org/x/crypto/ssh only.
//
// The shared golden vectors in testdata/vectors.json are byte-copied to
// core's enroll/testdata/ssh_vectors.json (plan ruling C17).
package cliapi
