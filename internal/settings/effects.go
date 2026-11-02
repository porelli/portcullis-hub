package settings

import (
	"github.com/portcullis/hub/internal/templates"
)

// Effect values (§13.9).
const (
	EffectNone    = "none"
	EffectReload  = "reload"
	EffectRestart = "restart"
)

// EffectOf maps an applies value to its effect: live/next_request/next_sign_in/
// account_creation → none, reload → reload, restart → restart. Unknown values
// → restart (strongest, fail safe).
func EffectOf(applies string) string {
	switch applies {
	case templates.AppliesLive,
		templates.AppliesNextRequest,
		templates.AppliesNextSignIn,
		templates.AppliesAccountCreation:
		return EffectNone
	case templates.AppliesReload:
		return EffectReload
	case templates.AppliesRestart:
		return EffectRestart
	default:
		return EffectRestart
	}
}

// Strongest returns the strongest effect from the given effects: restart >
// reload > none.
func Strongest(effects ...string) string {
	strongest := EffectNone
	for _, e := range effects {
		if e == EffectRestart {
			return EffectRestart
		}
		if e == EffectReload && strongest != EffectRestart {
			strongest = EffectReload
		}
	}
	return strongest
}
