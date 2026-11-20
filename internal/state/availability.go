package state

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/portcullis/hub/internal/runtime"
)

// Availability is an instance's priority and Runs on choice (contract
// §20.6, Kubernetes only; instances.<id>.availability, absent = the
// defaults normal / anywhere).
type Availability struct {
	Priority string `json:"priority" yaml:"priority"`
	RunsOn   RunsOn `json:"runs_on" yaml:"runs_on"`
}

// RunsOn is where an instance's pods may run: anywhere (no field),
// prefer (exactly one of Class home|cloud, Site or Nodes) or only (Nodes).
type RunsOn struct {
	Mode  string   `json:"mode" yaml:"mode"`
	Class string   `json:"class,omitempty" yaml:"class,omitempty"`
	Site  string   `json:"site,omitempty" yaml:"site,omitempty"`
	Nodes []string `json:"nodes,omitempty" yaml:"nodes,omitempty"`
}

// MaxRunsOnNodes is the most nodes a prefer or only choice names.
const MaxRunsOnNodes = 16

// The §20.6 refusal texts (Hub test TestAvailabilityRefusals pins them).
const (
	ErrTextPriority     = "priority must be critical, high, normal or low"
	ErrTextMode         = "runs_on mode must be anywhere, prefer or only"
	ErrTextAnywhere     = "runs_on anywhere takes no class, site or nodes"
	ErrTextPrefer       = "runs_on prefer takes exactly one of class, site or nodes"
	ErrTextOnly         = "runs_on only takes nodes, and no class or site"
	ErrTextSmallPrefer  = "small nodes take only instances pinned to them: use Only"
	ErrTextNeedsKube    = "availability needs Kubernetes"
	ErrTextUnknownNodeF = "unknown node %s"
)

// nodeNameRe is a node name as kubernetes.io/hostname carries it: a
// DNS-1123 subdomain that is also a label value (≤ 63).
var nodeNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,61}[a-z0-9])?$`)

// siteRe is a site name (a portcullis.io/site label value).
var siteRe = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)

// ValidNodeName reports whether n can be a node name.
func ValidNodeName(n string) bool { return nodeNameRe.MatchString(n) }

// PriorityOrDefault is a's priority, normal for nil.
func (a *Availability) PriorityOrDefault() string {
	if a == nil || a.Priority == "" {
		return runtime.PriorityNormal
	}
	return a.Priority
}

// ModeOrDefault is a's mode, anywhere for nil.
func (a *Availability) ModeOrDefault() string {
	if a == nil || a.RunsOn.Mode == "" {
		return runtime.RunsOnAnywhere
	}
	return a.RunsOn.Mode
}

// IsDefault: a is the defaults (normal / anywhere): stored as absent.
func (a *Availability) IsDefault() bool {
	return a == nil || (a.PriorityOrDefault() == runtime.PriorityNormal && a.ModeOrDefault() == runtime.RunsOnAnywhere &&
		a.RunsOn.Class == "" && a.RunsOn.Site == "" && len(a.RunsOn.Nodes) == 0)
}

// PriorityRank orders the priorities (low 0 … critical 3; -1 unknown).
func PriorityRank(p string) int {
	switch p {
	case runtime.PriorityLow:
		return 0
	case runtime.PriorityNormal, "":
		return 1
	case runtime.PriorityHigh:
		return 2
	case runtime.PriorityCritical:
		return 3
	}
	return -1
}

// Check refuses an availability §20.6 doesn't allow, with its texts. It
// judges the shape only: whether the nodes exist and which are small is
// the snapshot's (the Hub's PUT).
func (a Availability) Check() error {
	if a.Priority == "core" || PriorityRank(a.Priority) < 0 || a.Priority == "" {
		return errors.New(ErrTextPriority)
	}
	r := a.RunsOn
	switch r.Mode {
	case runtime.RunsOnAnywhere:
		if r.Class != "" || r.Site != "" || r.Nodes != nil {
			return errors.New(ErrTextAnywhere)
		}
	case runtime.RunsOnPrefer:
		n := 0
		for _, set := range []bool{r.Class != "", r.Site != "", r.Nodes != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			return errors.New(ErrTextPrefer)
		}
		switch {
		case r.Class == "small":
			return errors.New(ErrTextSmallPrefer)
		case r.Class != "":
			if r.Class != "home" && r.Class != "cloud" {
				return errors.New(ErrTextPrefer)
			}
		case r.Site != "":
			if !siteRe.MatchString(r.Site) {
				return errors.New(ErrTextPrefer)
			}
		default:
			if !nodesOK(r.Nodes) {
				return errors.New(ErrTextPrefer)
			}
		}
	case runtime.RunsOnOnly:
		if r.Class != "" || r.Site != "" || !nodesOK(r.Nodes) {
			return errors.New(ErrTextOnly)
		}
	default:
		return errors.New(ErrTextMode)
	}
	return nil
}

// nodesOK: 1–16 distinct node names.
func nodesOK(nodes []string) bool {
	if len(nodes) == 0 || len(nodes) > MaxRunsOnNodes {
		return false
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if !ValidNodeName(n) || seen[n] {
			return false
		}
		seen[n] = true
	}
	return true
}

// checkAvailability refuses a stored availability Check refuses.
func (s *AppState) checkAvailability() error {
	for id, e := range s.Instances {
		if e.Availability == nil {
			continue
		}
		if err := e.Availability.Check(); err != nil {
			return fmt.Errorf("instances.%s.availability: %v", id, err)
		}
	}
	return nil
}
