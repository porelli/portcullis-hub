// Package servers is the Hub's pure multi-server model (contract §17):
// server ids, tunnel address allocation on the link subnet, join codes,
// the enrolment proof and agent version skew. No hub, engine or network
// imports.
package servers

import (
	"errors"
	"regexp"
	"strings"
)

// IDRe is a server id (contract §17): a DNS label, at most 31 characters.
var IDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// PrimaryID names the primary, the local engine (spec §7): never a
// worker's id.
const PrimaryID = "primary"

// ValidID refuses anything but a worker's server id: IDRe, no trailing
// "-" (the id is the first label of <id>.node.portcullis.internal, which
// a DNS label can't end with), and never "primary".
func ValidID(id string) error {
	if id == PrimaryID {
		return errors.New("primary is the local server's name")
	}
	if !IDRe.MatchString(id) || strings.HasSuffix(id, "-") {
		return errors.New("a server id is a lower-case letter, then up to 30 lower-case letters, digits or \"-\", not ending in \"-\"")
	}
	return nil
}

// NodeName is a worker's certificate CN/SAN (pki_node role node-worker).
func NodeName(id string) string { return id + ".node.portcullis.internal" }
