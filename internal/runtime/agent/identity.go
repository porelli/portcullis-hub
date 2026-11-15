package agent

import (
	"context"

	"github.com/portcullis/hub/internal/agentapi"
)

// The identity, enrolment, network and leave calls (contract §17.5,
// pre-flight P6 order: nonce → proof → CSR → sign → PUT cert → PUT
// network → PUT wg).

func xr(name string) string { return agentapi.ExtraRoutes[name].Path }

// PeerSPKI is the sha256 of the SPKI the agent presented on the last
// connection (enrolling mode; nil before any).
func (b *Backend) PeerSPKI() []byte {
	b.c.mu.Lock()
	defer b.c.mu.Unlock()
	return append([]byte(nil), b.c.peerSPKI...)
}

// EnrolNonce is GET /v1/enrol/nonce.
func (b *Backend) EnrolNonce(ctx context.Context) ([]byte, error) {
	var n agentapi.EnrolNonce
	if err := b.c.json(ctx, "GET", xr("EnrolNonce"), nil, nil, &n, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	return n.Nonce, nil
}

// Enrol is POST /v1/enrol: the proof, then the agent's new keys' CSR.
func (b *Backend) Enrol(ctx context.Context, proof []byte, csrCN string) (agentapi.IdentityCSR, error) {
	var out agentapi.IdentityCSR
	err := b.c.json(ctx, "POST", xr("Enrol"), nil, agentapi.EnrolProof{Proof: proof, CSRCN: csrCN}, &out, agentapi.MaxJSON)
	return out, err
}

// IdentityCSR is POST /v1/identity/csr (renewal: a CSR from a new key).
func (b *Backend) IdentityCSR(ctx context.Context) (agentapi.IdentityCSR, error) {
	var out agentapi.IdentityCSR
	err := b.c.json(ctx, "POST", xr("IdentityCSR"), nil, nil, &out, agentapi.MaxJSON)
	return out, err
}

// PutIdentityCert is PUT /v1/identity/cert.
func (b *Backend) PutIdentityCert(ctx context.Context, c agentapi.IdentityCert) error {
	return b.c.json(ctx, "PUT", xr("IdentityCert"), nil, c, nil, 0)
}

// PutNetwork is PUT /v1/network.
func (b *Backend) PutNetwork(ctx context.Context, n agentapi.NetworkParams) error {
	return b.c.json(ctx, "PUT", xr("Network"), nil, n, nil, 0)
}

// PutIdentityWG is PUT /v1/identity/wg (the agent answers, then switches
// to its own WireGuard key).
func (b *Backend) PutIdentityWG(ctx context.Context, linkPub string) error {
	var out map[string]string
	return b.c.json(ctx, "PUT", xr("IdentityWG"), nil, agentapi.IdentityWG{LinkPub: linkPub}, &out, agentapi.MaxJSON)
}

// Leave is POST /v1/leave (Remove server).
func (b *Backend) Leave(ctx context.Context) error {
	return b.c.json(ctx, "POST", xr("Leave"), nil, nil, nil, 0)
}
