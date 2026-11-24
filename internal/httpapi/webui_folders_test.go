package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// foldersJS runs folders.js under node with body (after it).
func foldersJS(t *testing.T, body string) string {
	t.Helper()
	return nodeEval(t, "global.window = { escapeHtml: s => String(s) };\n"+webAsset(t, "folders.js")+"\n"+body)
}

// TestFolderUsedByGroupsSlots: Add shared folder's "Used by" rows are
// grouped by instance; numbered slots (share<n>_folder) show the slots in
// use with their share name ("unnamed" without one) and ONE free slot
// per instance (the lowest), never every empty slot; a slot this folder
// already uses is always listed; apps with named path settings keep one
// row per setting, labelled as before. The slot values come from the
// instance's settings panel.
func TestFolderUsedByGroupsSlots(t *testing.T) {
	out := foldersJS(t, `
const slot = n => [
  { key: 'share' + n + '_folder', label: 'Share ' + n + ' folder', type: 'path', section: 'Shared folders', folder: { access: 'write', runs_as: { uid_from: 'uid' } },
    requires_any: ['share' + n + '_readers', 'share' + n + '_writers'] },
  { key: 'share' + n + '_name', label: 'Share ' + n + ' name', type: 'string', section: 'Shared folders' },
  { key: 'share' + n + '_readers', label: 'Share ' + n + ' readers', type: 'groups' },
  { key: 'share' + n + '_writers', label: 'Share ' + n + ' writers', type: 'groups' },
];
const samba = { manifest: { name: 'Samba', settings: { options: [
  { key: 'homes', label: 'Home folders', type: 'path', folder: { access: 'write', runs_as: { uid_from: 'uid', gid_from: 'uid' } } },
  ...[1, 2, 3, 4, 5, 6, 7, 8].flatMap(slot),
] } } };
const jelly = { manifest: { name: 'Jellyfin', settings: { options: [
  { key: 'media', label: 'Media', type: 'path', description: 'Your films' },
  { key: 'extra', label: 'Extra', type: 'path' },
] } } };
window.loadCatalogInfo = async () => ({ samba, jellyfin: jelly });
const reads = [];
window.apiGet = async url => {
  reads.push(url);
  if (url === '/api/instances') return [{ id: 'samba', template: 'samba' }, { id: 'jellyfin', template: 'jellyfin' }, { id: 'smb2', template: 'samba' }];
  if (url === '/api/instances/samba/settings') return { instance: { share1_folder: '/srv/photos', share1_name: 'Photos', share3_name: 'Docs' } };
  throw new Error('no panel');
};
const F = window.PortcullisFolders;
F.pathOptions().then(opts => {
  const used = { 'samba/share4_folder': { folder: 'music' } };
  const before = { 'samba/share6_folder': { subpath: '', write: false } };
  const groups = F.usedByGroups(opts, used, before, 'mine').map(g => ({ instance: g.instance, app: g.app,
    rows: g.rows.map(r => ({ key: r.opt.key, label: r.label, next: !!r.next })) }));
  const next = F.usedByGroups(opts, used, before, 'mine').find(g => g.instance === 'samba').rows.find(r => r.next);
  process.stdout.write(JSON.stringify({ groups, reads, needs: next.opt.needs }));
});`)
	var got struct {
		Groups []struct {
			Instance, App string
			Rows          []struct {
				Key, Label string
				Next       bool
			}
		}
		Reads []string
		Needs []string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	rows := map[string][]string{}
	var order []string
	for _, g := range got.Groups {
		order = append(order, g.Instance)
		for _, r := range g.Rows {
			l := r.Key + "=" + r.Label
			if r.Next {
				l += " [next]"
			}
			rows[g.Instance] = append(rows[g.Instance], l)
		}
	}
	if strings.Join(order, ",") != "jellyfin,samba,smb2" {
		t.Errorf("groups = %v", order)
	}
	want := map[string]string{
		"jellyfin": "media=Media|extra=Extra",
		"samba": "share1_folder=“Photos” — Share 1 folder|share2_folder=free slot — Share 2 folder (the next free one) [next]|" +
			"share3_folder=“Docs” — Share 3 folder|share4_folder=unnamed — Share 4 folder|share6_folder=unnamed — Share 6 folder",
		// The panel unreadable: every slot by its label, no free-slot guess.
		"smb2": "share1_folder=Share 1 folder|share2_folder=Share 2 folder|share3_folder=Share 3 folder|share4_folder=Share 4 folder|" +
			"share5_folder=Share 5 folder|share6_folder=Share 6 folder|share7_folder=Share 7 folder|share8_folder=Share 8 folder",
	}
	for inst, w := range want {
		if g := strings.Join(rows[inst], "|"); g != w {
			t.Errorf("%s rows:\n got %s\nwant %s", inst, g, w)
		}
	}
	// The free slot says what it still needs in the app's Settings.
	if strings.Join(got.Needs, "|") != "Share 2 name|Share 2 readers or Share 2 writers" {
		t.Errorf("needs = %v", got.Needs)
	}
	// Only the instances with slots read their panel; no homes row (F34).
	if strings.Join(got.Reads, ",") != "/api/instances,/api/instances/samba/settings,/api/instances/smb2/settings" {
		t.Errorf("reads = %v", got.Reads)
	}
	if strings.Contains(out, "homes") {
		t.Errorf("a per-person path is offered: %s", out)
	}
}
