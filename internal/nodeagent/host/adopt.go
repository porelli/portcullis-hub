package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/portcullis/hub/internal/jsonstrict"
	na "github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/servers"
)

// The first node's nodeagent (plan Task 30 carry, contract §20.11): the
// cluster's first node never joins — core's `init` installed pcmesh and
// k3s on it — so its nodeagent is adopted by the install host's CLI:
//
//	nodeagent adopt-csr <id>   a new P-256 key (0600, never printed) and its
//	                           CSR for <id>.cluster.portcullis.internal on stdout
//	nodeagent adopt            stdin {"id", "mesh_ip", "site", "class",
//	                           "certificate", "ca"}: the CLI's node-cluster
//	                           certificate (Vault pki_node/sign/node-cluster)
//	                           for that key, the state, the unit started
//
// Only on a k3s server whose pcmesh key exists (init's /etc/wireguard/
// pcmesh.key, which the agent keeps using; wg-quick@pcmesh keeps the
// interface and the PORTCULLIS-MESH-IN chain, the agent the peers). Its
// certificate is renewed by the CLI the same way (`up`, `kube check`):
// nodeadm has no record of this node, so the agent never renews it itself
// (State.Adopted). A re-adoption must keep the cluster's CA and the id.

const adoptPEMFile = StateDir + "/node.adopt.pem"

// AdoptRequest is `nodeagent adopt`'s stdin (decoded strictly).
type AdoptRequest struct {
	ID          string `json:"id"`
	MeshIP      string `json:"mesh_ip"`
	Site        string `json:"site"`
	Class       string `json:"class"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// AdoptCSR writes a new key for id (replacing an earlier unused one) and
// returns its CSR (PEM).
func (a *Agent) AdoptCSR(ctx context.Context, id string) ([]byte, error) {
	if err := a.adoptable(ctx, id); err != nil {
		return nil, err
	}
	p, err := a.newKeyCSR(adoptPEMFile, id+"."+clusterDomain)
	if err != nil {
		return nil, err
	}
	return p.csrPEM, nil
}

// adoptable: k3s is a server here, pcmesh's key exists, the id is valid
// and, once adopted, the same.
func (a *Agent) adoptable(ctx context.Context, id string) error {
	if !idRe.MatchString(id) {
		return errors.New("invalid node id (^[a-z][a-z0-9-]{0,30}$)")
	}
	if a.k3sState(ctx) == "absent" || !a.fs.exists("/var/lib/rancher/k3s/server") {
		return errors.New("only the cluster's first node is adopted: no k3s server here (a new node joins with a join code)")
	}
	if _, err := a.meshKey(); err != nil {
		return fmt.Errorf("%v (init writes %s)", err, MeshKeyFile)
	}
	if b, err := a.fs.read(stateFile); err == nil {
		var st State
		if json.Unmarshal(b, &st) != nil || !st.Adopted || st.ID != id {
			return errors.New("this node's nodeagent joined the cluster (or is another node's): it isn't adopted again")
		}
	}
	return nil
}

// Adopt installs the adoption (or a renewed certificate): every check
// before anything is written; then the files, and the unit enabled and
// (re)started.
func (a *Agent) Adopt(ctx context.Context, r io.Reader) error {
	b, err := io.ReadAll(io.LimitReader(r, na.MaxBody+1))
	if err != nil || len(b) > na.MaxBody {
		return errors.New("the adoption request couldn't be read from stdin")
	}
	var q AdoptRequest
	if err := jsonstrict.Decode(b, &q); err != nil {
		return fmt.Errorf("the adoption request is malformed: %v", err)
	}
	if err := a.adoptable(ctx, q.ID); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(q.MeshIP)
	if err != nil || !meshPrefix.Contains(ip) || ip.String() != q.MeshIP {
		return errors.New("mesh_ip must be an address in 10.215.0.0/24")
	}
	if !idRe.MatchString(q.Site) || !servers.ValidClass(q.Class) {
		return errors.New("site must match ^[a-z][a-z0-9-]{0,30}$ and class be small, home or cloud")
	}
	ca, err := parseCertPEM([]byte(q.CA))
	if err != nil || !ca.IsCA {
		return errors.New("the ca isn't a CA certificate")
	}
	if old, err := a.fs.read(caFile); err == nil {
		if oc, err := parseCertPEM(old); err != nil || !oc.Equal(ca) {
			return errors.New("the ca isn't the one this node already trusts: nothing was changed")
		}
	}
	pend, err := a.loadKeyCSR(adoptPEMFile)
	if err != nil || pend == nil {
		return errors.New("no adoption key: run nodeagent adopt-csr first")
	}
	cn := q.ID + "." + clusterDomain
	leaf, err := parseCertPEM([]byte(q.Certificate))
	if err != nil || checkNodeLeafSkew(leaf, ca, cn, pend.csr.RawSubjectPublicKeyInfo, a.cfg.Now()) != nil {
		return fmt.Errorf("the certificate isn't a node-cluster certificate for %s and the adoption key, from the ca", cn)
	}
	bundle := nodeBundle(pend.key, []byte(q.Certificate))
	if _, err := nodeCert(bundle); err != nil {
		return err
	}
	st := State{V: 1, ID: q.ID, MeshIP: q.MeshIP, Role: "server", Site: q.Site, Class: q.Class, Servers: []string{}, Adopted: true}
	sb, _ := json.Marshal(st)
	for _, f := range []struct {
		path string
		data []byte
	}{{nodePEMFile, bundle}, {caFile, []byte(q.CA)}, {stateFile, sb}} {
		if err := a.fs.write(f.path, f.data, 0o600, 0o700); err != nil {
			return err
		}
	}
	a.fs.remove(adoptPEMFile)
	if err := a.fs.write(unitFile, []byte(UnitText()), 0o644, 0o755); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"restart", UnitName}} {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: args}); err != nil {
			return fmt.Errorf("starting %s: %v", UnitName, err)
		}
	}
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", UnitName}}); err != nil {
		return errors.New(UnitName + " didn't start: see journalctl -u " + UnitName)
	}
	a.log.Info("adopted", "id", q.ID, "not_after", leaf.NotAfter.UTC())
	return nil
}
