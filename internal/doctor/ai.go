package doctor

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// AI checks (contract §14.5 "AI support (NEW)", plan 4 Task 20). They
// judge what the Hub gathers per companion (Inputs.AI): its service's run
// state, the instance's sign-in template, the revocations the Hub owes
// (Hub.AIRevokeProblems) and the running image against the template's
// pin. Every finding of an instance links to its AI tab (Link.Tab "ai");
// the doctor never switches AI support itself.

// AIIn is one companion as the AI checks see it (the brief's fields plus
// labels, On and the revocation details AIRevokeProblems gives).
type AIIn struct {
	Instance, Companion string
	// Status is the companion service's container state as the Hub read
	// it: "running", "unhealthy", "exited", "missing", … ("" = unknown or
	// not read: not judged).
	Status string
	// Template is the instance's sign-in template in words (its
	// sentence); CertOnly: every way in needs a client certificate
	// (signin.NeedsCertificate, §8.1 / §15.11).
	Template string
	CertOnly bool
	// Revoking: credential entries stuck in revoking.
	Revoking int
	// ImagePinned is the template's pinned digest of the companion's
	// service ("sha256:…"; "" = not pinned, not judged), ImageRunning the
	// running container's ("" = not running or unknown).
	ImagePinned, ImageRunning string

	// Label / CompanionLabel name the app and the companion in findings.
	Label, CompanionLabel string
	// On: AI support is on for the companion now (master switch on, the
	// instance enabled, the companion switched on): only then are its
	// health, sign-in template and image judged.
	On bool
	// Pruned, NoHook, Recorded, Reason: Hub.AIRevokeProblems (Task 13b):
	// switched off by a template update with its revoke_all owed; the
	// template no longer has the hook; app_oauth people recorded whom no
	// hook can revoke; why.
	Pruned, NoHook bool
	Recorded       int
	Reason         string
	// Unmatched: app_oauth people who left before their app account could
	// be matched (T27): each gets a Dismiss in the finding.
	Unmatched []string
}

// Kinds of this file.
const (
	KindAICompanionUnhealthy  = "ai_companion_unhealthy"
	KindAIPolicyNeedsMTLS     = "ai_policy_needs_mtls"
	KindAICredentialsRevoking = "ai_credentials_revoking"
	KindAICompanionImageOld   = "ai_companion_image_old"

	// TabAI is Link.Tab for the instance's AI tab.
	TabAI = "ai"
)

func init() {
	Register(aiUnhealthyCheck{})
	Register(aiMTLSCheck{})
	Register(aiRevokingCheck{})
	Register(aiImageCheck{})
}

// AIFP is the fingerprint of an AI finding of kind about a companion.
func AIFP(kind, instance, companion string) string {
	return Fingerprint(kind, "instance:"+instance, "companion:"+companion)
}

func sortedAI(in *Inputs) []AIIn {
	out := slices.Clone(in.AI)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Instance != out[j].Instance {
			return out[i].Instance < out[j].Instance
		}
		return out[i].Companion < out[j].Companion
	})
	return out
}

func (a AIIn) app() string {
	if a.Label != "" {
		return a.Label
	}
	return a.Instance
}

func (a AIIn) companion() string {
	if a.CompanionLabel != "" {
		return a.CompanionLabel
	}
	return a.Companion
}

// aiLink is the finding's link to the instance's AI tab.
func aiLink(a AIIn) *Link { return &Link{Instance: a.Instance, Tab: TabAI} }

// shortDigest is a digest as findings show it (algorithm + 12 hex).
func shortDigest(d string) string {
	if alg, hex, ok := strings.Cut(d, ":"); ok && len(hex) > 12 {
		return alg + ":" + hex[:12]
	}
	return d
}

// ── ai_companion_unhealthy ───────────────────────────────

type aiUnhealthyCheck struct{}

func (aiUnhealthyCheck) Kind() string { return KindAICompanionUnhealthy }

func (aiUnhealthyCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, a := range sortedAI(in) {
		if !a.On || a.Status == "" || a.Status == "running" {
			continue
		}
		state := "isn't running (" + a.Status + ")"
		switch a.Status {
		case "unhealthy":
			state = "is unhealthy"
		case "missing":
			state = "has no container"
		}
		out = append(out, Finding{
			FP: AIFP(KindAICompanionUnhealthy, a.Instance, a.Companion), Kind: KindAICompanionUnhealthy, Severity: Problem,
			Title: fmt.Sprintf("%s's AI companion %s %s.", a.app(), a.companion(), state),
			Why: fmt.Sprintf("AI support is on for %s of %s, so AI clients reach it through the gate, but its service %s: their calls fail.",
				a.companion(), a.app(), state),
			Fix:   "Open the app's AI tab: restart the app, or switch the companion off; its logs are on the Logs tab.",
			Class: FixLink, Link: aiLink(a),
			Instances: []string{a.Instance},
			Inputs:    Digest([]string{a.Instance, a.Companion, a.Status}),
		})
	}
	return out
}

// ── ai_policy_needs_mtls (a canary) ──────────────────────

type aiMTLSCheck struct{}

func (aiMTLSCheck) Kind() string { return KindAIPolicyNeedsMTLS }

func (aiMTLSCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, a := range sortedAI(in) {
		if !a.On || !a.CertOnly {
			continue
		}
		tmpl := a.Template
		if tmpl == "" {
			tmpl = "its sign-in template"
		}
		out = append(out, Finding{
			FP: AIFP(KindAIPolicyNeedsMTLS, a.Instance, a.Companion), Kind: KindAIPolicyNeedsMTLS, Severity: Problem,
			Title: fmt.Sprintf("%s has AI support on, but its sign-in template needs a client certificate.", a.app()),
			Why: fmt.Sprintf("%s's sign-in template (%s) needs a client certificate on every sign-in, which AI clients can't present. A sign-in change switches AI support off first, so this should never happen: AI support on %s must be switched off.",
				a.app(), tmpl, a.companion()),
			Fix:   "Open the app's AI tab and switch the companion off, or choose a sign-in template with a way in without a client certificate.",
			Class: FixLink, Link: aiLink(a),
			Instances: []string{a.Instance},
			Inputs:    Digest([]any{a.Instance, a.Companion, a.CertOnly}),
		})
	}
	return out
}

// ── ai_credentials_revoking ──────────────────────────────

type aiRevokingCheck struct{}

func (aiRevokingCheck) Kind() string { return KindAICredentialsRevoking }

func (aiRevokingCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, a := range sortedAI(in) {
		if a.Revoking == 0 && a.Recorded == 0 && !a.Pruned && a.Reason == "" {
			continue
		}
		f := Finding{
			FP: AIFP(KindAICredentialsRevoking, a.Instance, a.Companion), Kind: KindAICredentialsRevoking, Severity: Warning,
			Inputs: Digest([]any{a.Instance, a.Companion, a.Revoking, a.Recorded, a.Pruned, a.NoHook, a.Reason}),
		}
		if a.Instance == "" {
			// The app_oauth record itself can't be read: nobody's owed
			// revocation can be told.
			f.Title = fmt.Sprintf("The Hub can't read its AI sign-in record (%s).", a.Companion)
			f.Why = fmt.Sprintf("The record of who connected app_oauth companions can't be read (%s), so the Hub can't revoke the app-side access of people who left.", a.Reason)
			f.Class = FixExplain
			f.Steps = []string{"Check the file's permissions and contents on the Hub's data volume (" + a.Companion + "); the Hub never replaces a file it can't read. Once it reads again the revocations resume."}
			out = append(out, f)
			continue
		}
		f.Instances = []string{a.Instance}
		reason := a.Reason
		if reason == "" {
			reason = "revocation pending"
		}
		if a.Revoking == 0 && a.Recorded == 0 && !a.Pruned {
			// app_oauth (T27): people who left before their app account
			// could be matched, unverifiable records, a failed record
			// write; the reason lines say what to do.
			f.Title = fmt.Sprintf("%s: the AI sign-ins of %s need attention.", a.app(), a.companion())
			f.Why = reason
			f.Fix = "Do what each line says in the app (its people or user settings), then dismiss the entry."
			f.Class, f.Link = FixLink, aiLink(a)
			for _, u := range a.Unmatched {
				f.Dismiss = append(f.Dismiss, Dismiss{Instance: a.Instance, Companion: a.Companion, User: u})
			}
			out = append(out, f)
			continue
		}
		switch {
		case a.Recorded > 0 && a.Revoking == 0:
			f.Title = fmt.Sprintf("%s: %d %s connected %s with the app's own sign-in and can't be revoked.", a.app(), a.Recorded,
				plural(int64(a.Recorded), "person", "people"), a.companion())
		default:
			n := a.Revoking
			what := fmt.Sprintf("%d AI %s", n, plural(int64(n), "credential is", "credentials are"))
			if n == 0 {
				what = "an owed revocation of every AI credential is"
			}
			f.Title = fmt.Sprintf("%s: %s stuck revoking for %s.", a.app(), what, a.companion())
		}
		var why []string
		if a.Revoking > 0 || a.Pruned {
			why = append(why, fmt.Sprintf("The Hub revokes an AI credential in the app before it forgets it; for %s of %s that keeps failing: %s. The gate never uses a revoking credential, but it may still work against the app directly.",
				a.companion(), a.app(), reason))
		}
		if a.Pruned {
			why = append(why, "A template update dropped the companion (or changed how it signs people in), so AI support for it was switched off and every credential it minted is owed a revocation.")
		}
		if a.Recorded > 0 {
			why = append(why, fmt.Sprintf("%d %s connected %s with the app's own sign-in (app_oauth); the template no longer has the companion's revoke hook, so the Hub can't take their app-side grants away.",
				a.Recorded, plural(int64(a.Recorded), "person", "people"), a.companion()))
		}
		f.Why = strings.Join(why, " ")
		if a.NoHook {
			// The app_oauth sentence already says the hook is gone.
			if a.Recorded == 0 {
				f.Why += " The template no longer has the hook the Hub would revoke them with."
			}
			f.Class = FixExplain
			f.Steps = []string{
				fmt.Sprintf("Revoke the access by hand in %s: its AI credentials are named portcullis-ai-… (app_oauth: the app's own OAuth grants of the people concerned).", a.app()),
				"Or bring back a template version that has the revoke hook: the Hub then revokes them at the next reconcile.",
			}
			if a.Instance != "" {
				f.Link = aiLink(a)
			}
		} else {
			f.Fix = "Open the app's AI tab: the revocation is retried at every reconcile; Revoke there retries it now, and the app's logs say why it fails."
			f.Class, f.Link = FixLink, aiLink(a)
		}
		out = append(out, f)
	}
	return out
}

// ── ai_companion_image_old ───────────────────────────────

type aiImageCheck struct{}

func (aiImageCheck) Kind() string { return KindAICompanionImageOld }

func (aiImageCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, a := range sortedAI(in) {
		if !a.On || a.ImagePinned == "" || a.ImageRunning == "" || a.ImagePinned == a.ImageRunning {
			continue
		}
		out = append(out, Finding{
			FP: AIFP(KindAICompanionImageOld, a.Instance, a.Companion), Kind: KindAICompanionImageOld, Severity: Warning,
			Title: fmt.Sprintf("%s's AI companion %s runs another image than the template pins.", a.app(), a.companion()),
			Why: fmt.Sprintf("The running container's image is %s, the template pins %s: the companion was vetted at the pinned digest only (a template update since, or an Expert override).",
				shortDigest(a.ImageRunning), shortDigest(a.ImagePinned)),
			Fix:   "Restart the app so the pinned image runs (check Expert → custom override if it names another image).",
			Class: FixLink, Link: aiLink(a),
			Instances: []string{a.Instance},
			Inputs:    Digest([]string{a.Instance, a.Companion, a.ImagePinned, a.ImageRunning}),
		})
	}
	return out
}
