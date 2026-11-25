package httpapi

import (
	"strings"
	"testing"
)

// Verified emails on People (contract §9.8): the badge, your own page's
// Verify email → code form, an editor's Mark verified, and what a failed
// send or confirm shows. directory.js's blocks run under node (skipped
// without node; CI has it).

func emailVerifyBlocks(t *testing.T) string {
	t.Helper()
	js := webAsset(t, "directory.js")
	var b strings.Builder
	for _, start := range []string{
		"  function emailBadge(u) {", "  function canMarkVerified(u) {", "  function emailVerifyHtml(u, st) {",
		"  function emailCodeOutcome(prev, user, err) {", "  async function finish(res) {",
	} {
		b.WriteString(jsBlock(t, js, start, "\n  }\n"))
	}
	return b.String()
}

const emailVerifyStubs = nodeEsc + `
let editable = new Set();
const canEdit = u => editable.has(u.username);
const fmtTime = s => 'T(' + s + ')';
function errText(err) { return (err && err.message) || 'failed'; }
`

func TestPeoplePageBadges(t *testing.T) {
	script := emailVerifyStubs + emailVerifyBlocks(t) + `
(async () => {
const out = {};
const bob = { username: 'bob', email: 'bob@example.org', email_verified: false };
const ver = { username: 'carl', email: 'carl@example.org', email_verified: true };
const none = { username: 'nomail', email: '' };
out.badgeNo = emailBadge(bob);
out.badgeYes = emailBadge(ver);
out.badgeNone = emailBadge(none);
// Your own unverified email: Verify email; no Mark verified.
const me = Object.assign({ self: true }, bob);
editable.add('bob');
out.own = emailVerifyHtml(me, null);
out.ownSent = emailVerifyHtml(me, { user: 'bob', sent: true, expires_at: 'X', note: '' });
out.ownOther = emailVerifyHtml(me, { user: 'carl', sent: true });
out.ownVerified = emailVerifyHtml(Object.assign({}, me, { email_verified: true }), null);
// Someone else's: Mark verified for an editor only, never Verify email.
out.editor = emailVerifyHtml(bob, null);
editable.delete('bob');
out.viewer = emailVerifyHtml(bob, null);
editable.add('carl');
out.editorVerified = emailVerifyHtml(ver, null);
out.noEmail = emailVerifyHtml(none, null);
// Failed confirms and sends.
const prev = { user: 'bob', sent: true, expires_at: 'X' };
const e = (status, msg, left) => { const x = new Error(msg); x.status = status; x.attemptsLeft = left; return x; };
out.wrong4 = emailCodeOutcome(prev, 'bob', e(400, 'wrong code', 4));
out.wrong1 = emailCodeOutcome(prev, 'bob', e(400, 'wrong code', 1));
out.wrong0 = emailCodeOutcome(prev, 'bob', e(400, 'wrong code', 0));
out.gone = emailCodeOutcome(prev, 'bob', e(410, 'this code has expired: ask for a new one'));
out.off = emailCodeOutcome(null, 'bob', e(409, "mail isn't set up on this server"));
out.many = emailCodeOutcome(prev, 'bob', e(429, 'too many codes: try again later'));
// finish() reads attempts_left from the 400 body.
const res = (status, text) => ({ ok: status < 300, status, text: async () => text });
try { await finish(res(400, '{"attempts_left":3}\n')); } catch (err) { out.fin = { status: err.status, left: err.attemptsLeft, msg: err.message }; }
try { await finish(res(410, 'this code has expired: ask for a new one\n')); } catch (err) { out.fin410 = { status: err.status, left: err.attemptsLeft === undefined ? -1 : err.attemptsLeft, msg: err.message }; }
console.log(JSON.stringify(out));
})();
`
	type outcome struct {
		User string
		Sent bool
		Note string
	}
	type fin struct {
		Status, Left int
		Msg          string
	}
	var got struct {
		BadgeNo, BadgeYes, BadgeNone, Own, OwnSent, OwnOther, OwnVerified, Editor, Viewer, EditorVerified, NoEmail string
		Wrong4, Wrong1, Wrong0, Gone, Off, Many                                                                    outcome
		Fin, Fin410                                                                                                fin
	}
	nodeJSON(t, script, &got)
	if !strings.Contains(got.BadgeNo, ">Not verified</span>") || !strings.Contains(got.BadgeNo, `data-email-state="unverified"`) {
		t.Errorf("unverified badge: %s", got.BadgeNo)
	}
	if !strings.Contains(got.BadgeYes, ">Verified</span>") || !strings.Contains(got.BadgeYes, "pd-pill ok") {
		t.Errorf("verified badge: %s", got.BadgeYes)
	}
	if got.BadgeNone != "" || got.NoEmail != "" {
		t.Errorf("no email: %q %q", got.BadgeNone, got.NoEmail)
	}
	if !strings.Contains(got.Own, `data-act="email-verify-send"`) || !strings.Contains(got.Own, ">Verify email</button>") ||
		strings.Contains(got.Own, "email-mark-verified") || strings.Contains(got.Own, "pd-email-code") {
		t.Errorf("own page: %s", got.Own)
	}
	for _, want := range []string{`id="pd-email-code"`, `autocomplete="one-time-code"`, `data-act="email-verify-confirm"`, ">Send a new code</button>", "We sent a code to bob@example.org. It expires at T(X)."} {
		if !strings.Contains(got.OwnSent, want) {
			t.Errorf("own page, code sent, lacks %q: %s", want, got.OwnSent)
		}
	}
	if strings.Contains(got.OwnOther, "pd-email-code") {
		t.Errorf("another person's form shown: %s", got.OwnOther)
	}
	if strings.Contains(got.OwnVerified, "email-verify-send") || !strings.Contains(got.OwnVerified, ">Verified</span>") {
		t.Errorf("own verified: %s", got.OwnVerified)
	}
	if !strings.Contains(got.Editor, `data-act="email-mark-verified" data-user="bob"`) || strings.Contains(got.Editor, "email-verify-send") {
		t.Errorf("editor: %s", got.Editor)
	}
	if strings.Contains(got.Viewer, "email-mark-verified") || strings.Contains(got.EditorVerified, "email-mark-verified") {
		t.Errorf("viewer %s / verified %s", got.Viewer, got.EditorVerified)
	}
	if !got.Wrong4.Sent || got.Wrong4.Note != "Wrong code: 4 tries left." || got.Wrong1.Note != "Wrong code: 1 try left." {
		t.Errorf("wrong: %+v %+v", got.Wrong4, got.Wrong1)
	}
	if got.Wrong0.Sent || !strings.Contains(got.Wrong0.Note, "Ask for a new one") {
		t.Errorf("used up: %+v", got.Wrong0)
	}
	if got.Gone.Sent || got.Gone.Note != "this code has expired: ask for a new one" {
		t.Errorf("expired: %+v", got.Gone)
	}
	if got.Off.Sent || got.Off.Note != "mail isn't set up on this server" || !got.Many.Sent || got.Many.Note != "too many codes: try again later" {
		t.Errorf("send refusals: %+v %+v", got.Off, got.Many)
	}
	if got.Fin != (fin{400, 3, "wrong code"}) || got.Fin410 != (fin{410, -1, "this code has expired: ask for a new one"}) {
		t.Errorf("finish: %+v %+v", got.Fin, got.Fin410)
	}
	// Wired: the People list shows the badge, the person page the email
	// line, the clicks reach the routes.
	js := webAsset(t, "directory.js")
	for _, want := range []string{
		"esc(u.email) + ' ' + emailBadge(u)",
		`'<div class="pd-pp-email" data-pp-email="'`,
		"case 'email-verify-send': return sendEmailCode(user);",
		"case 'email-verify-confirm': return confirmEmailCode(user);",
		"api('POST', '/api/me/email/verify', {})",
		"api('POST', '/api/me/email/verify/confirm', { code })",
		"'/email/verified', {})",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("directory.js lacks %q", want)
		}
	}
}
