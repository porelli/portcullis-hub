package templates

import "fmt"

// The verified_email option type (integration contracts §13.2, §9.8): the
// person's verified email, for apps whose accounts are keyed by email.
// The Hub sets one value per person (never an admin value) and delivers
// it only into the people section of data files; a person without a
// verified email is left out of those files (§13.7). The type is generic:
// any email-keyed template can declare it.

// validateVerifiedEmail checks o's structural rules against m: a template
// whose access group is the population (group_access and access_group;
// with or without routers), none of the fields an admin-valued person
// option takes, self_visible exactly false, and at least one delivery,
// each a plain {file: {name, field}} (env, claim, header, hook, a bare
// delivery or a render are refused). The declared files are the
// specCheck's (verifiedEmail).
func validateVerifiedEmail(o *Option, m *Manifest) error {
	a := &m.Auth
	if !a.GroupAccess || a.AccessGroup == "" {
		return fmt.Errorf("a verified_email needs group_access: true and an auth.access_group (whose members' emails it delivers)")
	}
	if err := personFieldsRefused(o, fieldUse{"checks", o.Checks != nil}); err != nil {
		return err
	}
	if o.SelfVisible == nil || *o.SelfVisible {
		return fmt.Errorf("a verified_email needs self_visible: false (never shown on My apps)")
	}
	if len(o.Delivery) == 0 {
		return fmt.Errorf("a verified_email needs a file delivery ({file: {name, field}}: the people section of a data file)")
	}
	for _, d := range o.Delivery {
		if d.File == nil || d.Env != "" || d.Claim != nil || d.Header != nil || d.Hook != "" || d.Bare != "" || d.Render != nil || d.File.Render != nil {
			return fmt.Errorf("a verified_email takes only file deliveries ({file: {name, field}}); env, claim, header and hook deliveries are refused")
		}
	}
	return nil
}

// verifiedEmail checks a verified_email option (§13.2): the structural
// rules, then each file delivery against the declared files (one writer
// per field), and applies: live only into files a hook applies.
func (v *specCheck) verifiedEmail(o *Option) error {
	if err := validateVerifiedEmail(o, v.m); err != nil {
		return err
	}
	for _, d := range o.Delivery {
		if err := v.file(o, d.File); err != nil {
			return err
		}
		if o.Applies == AppliesLive && v.files_[d.File.Name].OnMembershipChange != MembershipHook {
			return fmt.Errorf("applies: live means a hook applies it: file %s needs on_membership_change: hook", d.File.Name)
		}
	}
	return nil
}
