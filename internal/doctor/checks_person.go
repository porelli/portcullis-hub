package doctor

import (
	"fmt"
	"sort"
)

// KindPersonOption: per-person options (project 1) no group sets, or
// whose rows reach nobody (contract §14.5). All link to the option.
const KindPersonOption = "person_option"

func init() { Register(personOptionCheck{}) }

type personOptionCheck struct{}

func (personOptionCheck) Kind() string { return KindPersonOption }

func (personOptionCheck) Run(in *Inputs) []Finding {
	ps := append([]PersonIn(nil), in.Person...)
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Instance != ps[j].Instance {
			return ps[i].Instance < ps[j].Instance
		}
		return ps[i].Key < ps[j].Key
	})
	var out []Finding
	for _, p := range ps {
		label := p.Label
		if label == "" {
			label = p.Key
		}
		link := func(f Finding) Finding {
			f.Kind, f.Class = KindPersonOption, FixLink
			f.Link = &Link{Instance: p.Instance, Option: p.Key}
			f.Instances = []string{p.Instance}
			return f
		}
		bound := 0
		for _, r := range p.Rows {
			if r.GroupID == 0 {
				continue // unbound: grants nothing (plan 1 P7)
			}
			if !r.Exists {
				out = append(out, link(Finding{
					FP: Fingerprint(KindPersonOption, p.Instance, p.Key, "gone", r.Group), Severity: Warning,
					Title:  fmt.Sprintf("%s: %s has a value for group %s, which no longer exists.", p.Instance, label, r.Group),
					Why:    "The group was deleted or re-created since the row was saved: the row grants nothing.",
					Fix:    "Open the setting and remove the row, or bind it to the group again.",
					Inputs: Digest([]any{r.Group, r.GroupID}),
				}))
				continue
			}
			bound++
			if r.Members == 0 {
				out = append(out, link(Finding{
					FP: Fingerprint(KindPersonOption, p.Instance, p.Key, "empty", r.Group), Severity: Warning,
					Title:  fmt.Sprintf("%s: %s has a value for group %s, which has nobody with access to %s.", p.Instance, label, r.Group, p.Instance),
					Why:    "Nobody in the instance's population is in that group, so the value reaches nobody.",
					Fix:    "Open the setting and check the row's group, or add people with access to it.",
					Inputs: Digest([]any{r.Group, r.GroupID}),
				}))
			}
		}
		if bound > 0 {
			continue
		}
		f := Finding{
			FP:       Fingerprint(KindPersonOption, p.Instance, p.Key, "no_rows"),
			Severity: Info,
			Title:    fmt.Sprintf("%s: %s has no group values; everyone with access gets the default (%s).", p.Instance, label, p.DefaultDisplay),
			Why:      "No row binds a value to a group, so the per-person option acts like a single value.",
			Fix:      "Open the setting to give groups their own values.",
			Inputs:   Digest([]any{p.DefaultDisplay, p.Requires}),
		}
		if p.Requires != nil {
			f.Severity = Warning
			f.Why = "The template asks for group values: " + p.Requires.Reason
		}
		out = append(out, link(f))
	}
	return out
}
