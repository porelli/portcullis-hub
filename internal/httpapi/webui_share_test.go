package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Hub UX reorganisation Task 14: the Usage tab's Share view
// (web/share.js) and its inline-SVG donuts (web/donut.js).

const shareFixture = `
global.window = global.window || {};
const GiB = 1073741824;
const VIEW = {
  window: 'last',
  hosts: {
    primary: { name: 'hub-1', cpus: 8, memory_bytes: 16 * GiB, cpu_used_cores: 3, mem_used_bytes: 8 * GiB, blk_read_bps: 1000, blk_write_bps: 1000 },
    w1: { name: 'worker <one>', cpus: 4, memory_bytes: 8 * GiB, cpu_used_cores: 1, mem_used_bytes: 2 * GiB, blk_read_bps: null, blk_write_bps: null },
  },
  apps: [
    { instance: 'a', name: 'Alpha <b>', server: 'primary', status: 'running',
      totals: { cpu_cores: 1, mem_bytes: 2 * GiB, net_rx_bps: 100, net_tx_bps: 50, blk_read_bps: 200, blk_write_bps: 100 },
      containers: [
        { service: 'web', number: 1, sample: { cpu_cores: 0.75, mem_bytes: 1.5 * GiB, net_rx_bps: 100, net_tx_bps: 50, blk_read_bps: 200, blk_write_bps: 100 } },
        { service: 'worker', number: 1, sample: { cpu_cores: 0.25, mem_bytes: 0.5 * GiB, net_rx_bps: null, net_tx_bps: null, blk_read_bps: 0, blk_write_bps: 0 },
          not_measured: { net_rx_bps: 'not measured: the container uses the host\'s network', net_tx_bps: 'not measured: the container uses the host\'s network' } } ] },
    { instance: 'b', name: 'Beta', server: 'primary', status: 'running',
      totals: { cpu_cores: 0.5, mem_bytes: 1 * GiB, net_rx_bps: 10, net_tx_bps: 10, blk_read_bps: 100, blk_write_bps: 0 }, containers: [] },
    { instance: 'c', name: 'Gamma', server: 'w1', status: 'running',
      totals: { cpu_cores: 0.5, mem_bytes: 1 * GiB, net_rx_bps: 5, net_tx_bps: 5, blk_read_bps: null, blk_write_bps: null }, containers: [] },
    { instance: 'n', name: 'Nil', server: 'primary', status: 'not_measured', why: 'w2 is unreachable',
      totals: { cpu_cores: null, mem_bytes: null, net_rx_bps: null, net_tx_bps: null, blk_read_bps: null, blk_write_bps: null }, containers: [] },
  ],
  core: { instance: 'core', name: 'Core', server: 'primary', totals: { cpu_cores: 0.5, mem_bytes: 1 * GiB, net_rx_bps: 10, net_tx_bps: 10, blk_read_bps: 100, blk_write_bps: 100 }, containers: [] },
};
const STORAGE = {
  disks: [{ server: 'primary', dev: 7, device: '0:7', role: 'docker_data', path: '/var/lib/docker', total_bytes: 1000, free_bytes: 300 },
    { server: 'primary', dev: 9, device: '0:9', role: 'folder_root', path: '/srv/media', total_bytes: 500, free_bytes: 400 },
    { server: 'w1', dev: 7, device: '0:7', role: 'docker_data', total_bytes: 100, free_bytes: 50 },
    { server: 'primary', dev: 2065, device: '8:17', role: 'other', path: '/mnt/data', total_bytes: 100, free_bytes: 100 },
    { server: 'primary', dev: 2081, device: '8:33', role: 'agent_data', total_bytes: 100, free_bytes: 100 }],
  apps: [
    { instance: 'a', name: 'Alpha <b>', items: [
      { kind: 'volume', target: 'a_data', dev: 7, alloc_bytes: 100, in_total: true, services: ['web.1'] },
      { kind: 'volume', target: 'a_shared', dev: 7, alloc_bytes: 50, in_total: true, services: ['web.1', 'worker.1'] },
      { kind: 'layer', target: 'web.1', alloc_bytes: 10, in_total: true },
      { kind: 'image', target: 'img:1', alloc_bytes: 200, in_total: false },
      { kind: 'folder', target: 'media', dev: 9, alloc_bytes: 80, in_total: false },
      { kind: 'hub_files', target: 'Hub-managed files', alloc_bytes: null, in_total: false } ] },
    { instance: 'b', name: 'Beta', items: [
      { kind: 'volume', target: 'b_data', dev: 7, alloc_bytes: 40, in_total: true },
      { kind: 'image', target: 'img:1', alloc_bytes: 200, in_total: false },
      { kind: 'image', target: 'img:2', alloc_bytes: 30, in_total: false } ] },
    { instance: 'c', name: 'Gamma', items: [{ kind: 'volume', target: 'c_data', dev: 7, alloc_bytes: 20, in_total: true }] },
  ],
  folders: [{ id: 'media', name: 'Media', alloc_bytes: 80 }],
  core: [{ kind: 'volume', target: 'hub_data', dev: 7, alloc_bytes: 60, in_total: true }, { kind: 'image', target: 'img:core', alloc_bytes: 70, in_total: false }],
};
`

func shareEval(t *testing.T, body string) map[string]any {
	t.Helper()
	out := nodeEval(t, shareFixture+webAsset(t, "donut.js")+"\nconst D = window.PortcullisDonut;\nconst r = {};\n"+body+"\nprocess.stdout.write(JSON.stringify(r));\n")
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

// TestDonutGeometry: a single 100 % slice is two arcs; nothing to draw
// is the empty ring with "nothing measured" (or "not measured" and the
// reason); every number in the markup is a plain decimal; labels only in
// <title>, escaped.
func TestDonutGeometry(t *testing.T) {
	r := shareEval(t, `
r.one = D.svg([{ key: 'a', label: 'A', value: 5, cls: 'share-c1' }], { size: 160, hole: 0.6 });
r.zero = D.svg([{ key: 'a', label: 'A', value: 0 }, { key: 'b', label: 'B', value: 0 }], { size: 160, hole: 0.6 });
r.nil = D.svg([{ key: 'a', label: 'A', value: null }, { key: 'b', label: 'B', value: 'x' }], { size: 160, hole: 0.6, why: 'not measured on Kubernetes' });
r.over = D.slices({ hosts: { primary: { cpus: 2, cpu_used_cores: 1 } }, apps: [{ instance: 'a', name: 'A', server: 'primary', totals: { cpu_cores: 1.5 } }, { instance: 'b', name: 'B', server: 'primary', totals: { cpu_cores: 1.5 } }], core: null }, 'cpu', 'primary');
r.overSvg = D.svg(r.over.slices, { size: 160, hole: 0.6, total: r.over.total });
r.mixed = D.svg([{ key: 'a', label: '<script>x</script>', value: 1, cls: 'share-c1', app: 'a"b' }, { key: 'b', label: 'B & co', value: 2, cls: 'share-c2' }, { key: 'c', label: 'C', value: NaN }, { key: 'd', label: 'D', value: Infinity }, { key: 'e', label: 'E', value: -3 }], { size: 120, hole: 0.5, center: '3 <i>', tab: true, label: 'CPU <x> donut' });
`)
	one, _ := r["one"].(string)
	if n := strings.Count(one, " A "); n != 2 || strings.Contains(one, "NaN") || strings.Count(one, "<path") != 1 {
		t.Errorf("one 100%% slice: %d arcs:\n%s", n, one)
	}
	zero, _ := r["zero"].(string)
	if !strings.Contains(zero, "share-track") || !strings.Contains(zero, "nothing measured") || strings.Contains(zero, "<path") {
		t.Errorf("[0, 0]:\n%s", zero)
	}
	nil_, _ := r["nil"].(string)
	if !strings.Contains(nil_, ">not measured<title>not measured on Kubernetes</title>") || strings.Contains(nil_, "<path") || strings.Contains(nil_, "not measured: not measured") {
		t.Errorf("all nil:\n%s", nil_)
	}
	var over struct {
		Slices []struct {
			Key   string
			Value float64
		}
	}
	b, _ := json.Marshal(r["over"])
	json.Unmarshal(b, &over)
	for _, s := range over.Slices {
		if s.Value < 0 {
			t.Errorf("negative slice %s %v", s.Key, s.Value)
		}
		if s.Key == "other" && s.Value != 0 {
			t.Errorf("other = %v, want 0", s.Value)
		}
	}
	for _, k := range []string{"one", "zero", "nil", "overSvg", "mixed"} {
		s, _ := r[k].(string)
		for _, m := range regexp.MustCompile(`(?:[a-z-]+)="([^"]*)"`).FindAllStringSubmatch(s, -1) {
			if !strings.Contains(m[0], "class=") && !strings.Contains(m[0], "data-") && !strings.Contains(m[0], "role=") && !strings.Contains(m[0], "aria-") && !strings.Contains(m[0], "text-anchor") && !strings.Contains(m[0], "dominant-baseline") && !strings.Contains(m[0], "tabindex") {
				for _, tok := range regexp.MustCompile(`[ ,]+`).Split(strings.TrimSpace(m[1]), -1) {
					if tok == "M" || tok == "A" || tok == "" {
						continue
					}
					if !regexp.MustCompile(`^-?\d+(\.\d+)?$`).MatchString(tok) {
						t.Errorf("%s: %q in %s", k, tok, m[0])
					}
				}
			}
		}
	}
	mixed, _ := r["mixed"].(string)
	if strings.Contains(mixed, "<script>") || !strings.Contains(mixed, "<title>&lt;script&gt;x&lt;/script&gt;</title>") || !strings.Contains(mixed, "<title>B &amp; co</title>") ||
		!strings.Contains(mixed, `data-share-app="a&quot;b" tabindex="0" role="button" aria-label="&lt;script&gt;x&lt;/script&gt;, open its containers"`) ||
		!strings.Contains(mixed, `role="group" aria-label="CPU &lt;x&gt; donut"`) || strings.Contains(mixed, `<svg class="share-donut" viewBox="0 0 120.00 120.00" width="120.00" height="120.00" role="img"`) || regexp.MustCompile(`<svg[^>]*aria-hidden`).MatchString(mixed) || strings.Count(mixed, "<path") != 2 || !strings.Contains(mixed, ">3 &lt;i&gt;</text>") {
		t.Errorf("mixed:\n%s", mixed)
	}
	// Outside <title> and the center text, no label text.
	if strings.Contains(regexp.MustCompile(`<title>.*?</title>`).ReplaceAllString(mixed, ""), "B &amp; co") {
		t.Errorf("a label outside <title>:\n%s", mixed)
	}
}

type shareDonut struct {
	Slices []struct {
		Key   string
		Label string
		Value float64
		Cls   string
	}
	Total   *float64
	Caption string
	Missing []struct{ Label, Why string }
	Why     string
}

func (d shareDonut) keyed() string {
	var out []string
	for _, s := range d.Slices {
		out = append(out, s.Key+"="+jsonOf(s.Value))
	}
	return strings.Join(out, " ")
}

// TestShareSlicesNode: each metric's slices on the primary (apps, core,
// other, free), network apps-only, storage per disk (apps by dev, core,
// folders, images once on the engine's disk, other used, free), a worker,
// and the 1 h view read the same way.
func TestShareSlicesNode(t *testing.T) {
	r := shareEval(t, `
for (const m of ['cpu', 'mem', 'io', 'net']) r[m] = D.slices(VIEW, m, 'primary');
r.w1cpu = D.slices(VIEW, 'cpu', 'w1');
r.w1io = D.slices(VIEW, 'io', 'w1');
r.d7 = D.slices(VIEW, 'storage', 'primary', { storage: STORAGE, dev: 7 });
r.d9 = D.slices(VIEW, 'storage', 'primary', { storage: STORAGE, dev: 9 });
r.w1d7 = D.slices(VIEW, 'storage', 'w1', { storage: STORAGE, dev: 7 });
r.disks = D.disks(STORAGE, 'primary').map(d => d.dev);
`)
	get := func(k string) shareDonut {
		var d shareDonut
		b, _ := json.Marshal(r[k])
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	G := float64(1 << 30)
	_ = G
	want := map[string]string{
		"cpu":   "app:a=1 app:b=0.5 core=0.5 other=1 free=5",
		"mem":   "app:a=2147483648 app:b=1073741824 core=1073741824 other=4294967296 free=8589934592",
		"io":    "app:a=300 app:b=100 core=200 other=1400",
		"net":   "app:a=150 app:b=20",
		"w1cpu": "app:c=0.5 other=0.5 free=3",
		"w1io":  "",
		"d7":    "app:a=160 app:b=40 core=60 images=300 other=140 free=300",
		"d9":    "folders=80 other=20 free=400",
		"w1d7":  "app:c=20 other=30 free=50",
	}
	for k, w := range want {
		if g := get(k).keyed(); g != w {
			t.Errorf("%s = %q, want %q", k, g, w)
		}
	}
	if d := get("net"); d.Caption != "of measured app traffic (no host-wide figure)" {
		t.Errorf("net caption %q", d.Caption)
	}
	if d := get("cpu"); len(d.Missing) != 1 || d.Missing[0].Label != "Nil" || d.Missing[0].Why != "w2 is unreachable" || d.Total == nil || *d.Total != 8 {
		t.Errorf("cpu missing/total: %+v", d)
	}
	if d := get("w1io"); d.Why == "" {
		t.Error("a host without disk IO figures isn't 'not measured'")
	}
	if g := jsonOf(r["disks"]); g != "[7,9,2065,2081]" {
		t.Errorf("primary disks %s", g)
	}
	// Colour follows the app: Alpha c1 (most memory), Beta c2, core c0.
	for _, s := range get("cpu").Slices {
		if (s.Key == "app:a" && s.Cls != "share-c1") || (s.Key == "app:b" && s.Cls != "share-c2") || (s.Key == "core" && s.Cls != "share-c0") {
			t.Errorf("colour of %s: %s", s.Key, s.Cls)
		}
	}
}

// shareDOM: a document for share.js: an element whose innerHTML is kept
// as a string; act() stands in for the delegated clicks.
const shareDOM = `
global.document = { activeElement: null };
const el = { innerHTML: '', dataset: {}, contains: () => false, addEventListener() {} };
`

func shareRender(t *testing.T, body string) map[string]any {
	t.Helper()
	out := nodeEval(t, shareFixture+shareDOM+webAsset(t, "donut.js")+webAsset(t, "share.js")+"\nconst S = window.PortcullisShare;\nconst r = {};\nconst wins = [];\n"+body+"\nprocess.stdout.write(JSON.stringify(r));\n")
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

// TestShareDrillNode: an app's slice opens its containers' donuts
// ("<service>.<number>", a volume shared by two containers its own slice,
// a container without a figure "not measured" with the reason); "← All
// apps" goes back; slices are keyboard focusable.
func TestShareDrillNode(t *testing.T) {
	r := shareRender(t, `
S.render(el, { view: VIEW, storage: STORAGE, server: 'primary', window: 'last', onWindow: w => wins.push(w) });
r.top = el.innerHTML;
S.act('app', 'a');
r.app = el.innerHTML;
r.st = S.state();
S.act('back');
r.back = el.innerHTML;
S.act('window', '1h');
r.wins = wins.slice();
r.drillStorage = window.PortcullisDonut.drill(VIEW, 'a', 'storage', { storage: STORAGE });
`)
	top, _ := r["top"].(string)
	for _, want := range []string{`data-share-app="a" tabindex="0" role="button"`, `<button type="button" class="share-link" data-share-app="a">Alpha &lt;b&gt;</button>`, "Alpha &lt;b&gt;", "not measured: w2 is unreachable", "of the host&#39;s CPUs"} {
		if !strings.Contains(top, want) {
			t.Errorf("server view lacks %q", want)
		}
	}
	if strings.Contains(top, "Alpha <b>") {
		t.Error("an app name as markup")
	}
	app, _ := r["app"].(string)
	for _, want := range []string{"data-share-back", "← All apps", "web.1", "worker.1", "shared by web.1, worker.1", "not measured: the container uses the host&#39;s network"} {
		if !strings.Contains(app, want) {
			t.Errorf("drill lacks %q", want)
		}
	}
	if g := jsonOf(r["st"]); g != `{"app":"a","server":"primary","window":"last"}` {
		t.Errorf("state %s", g)
	}
	if back, _ := r["back"].(string); back != top {
		t.Error("← All apps doesn't give the server view back")
	}
	if g := jsonOf(r["wins"]); g != `["1h"]` {
		t.Errorf("window toggle: %s", g)
	}
	var d shareDonut
	b, _ := json.Marshal(r["drillStorage"])
	json.Unmarshal(b, &d)
	if g := d.keyed(); g != "web.1=110 shared:web.1,worker.1=50" {
		t.Errorf("drill storage %q", g)
	}
}

// TestShareServersNode: a picker lists every server; switching shows that
// server's apps only; a host with a why shows the text instead of donuts
// (Kubernetes: every host figure null).
func TestShareServersNode(t *testing.T) {
	r := shareRender(t, `
S.render(el, { view: VIEW, storage: STORAGE, server: 'primary', window: 'last' });
r.primary = el.innerHTML;
S.act('server', 'w1');
r.w1 = el.innerHTML;
const kube = { window: 'last', hosts: { primary: { name: 'k', cpus: null, memory_bytes: null, cpu_used_cores: null, mem_used_bytes: null, blk_read_bps: null, blk_write_bps: null, why: 'not measured on Kubernetes' } },
  apps: [{ instance: 'a', name: 'A', server: 'primary', totals: { cpu_cores: 0.2, mem_bytes: 100 }, containers: [] }], core: { instance: 'core', server: 'primary', status: 'not_measured', why: 'not measured on Kubernetes yet', totals: {}, containers: [] } };
S.render(el, { view: kube, storage: { disks: [] }, server: 'primary', window: 'last' });
r.kube = el.innerHTML;
// A poll with the same data doesn't touch the markup.
let writes = 0; let html = el.innerHTML;
Object.defineProperty(el, 'innerHTML', { get() { return html; }, set(v) { writes++; html = v; } });
S.update(kube, { disks: [] });
r.writes = writes;
`)
	p, _ := r["primary"].(string)
	if !strings.Contains(p, `<select data-share-server><option value="primary" selected>hub-1 (primary)</option><option value="w1">worker &lt;one&gt;</option></select>`) {
		t.Errorf("server picker:\n%s", p)
	}
	if !strings.Contains(p, "Alpha") || strings.Contains(p, "Gamma") {
		t.Error("the primary shows a worker's app")
	}
	w1, _ := r["w1"].(string)
	if !strings.Contains(w1, "Gamma") || strings.Contains(w1, "Alpha") || !strings.Contains(w1, `<option value="w1" selected>`) {
		t.Errorf("w1:\n%s", w1)
	}
	k, _ := r["kube"].(string)
	if !strings.Contains(k, `<p class="usage-warn" data-share-why>not measured on Kubernetes</p>`) || strings.Contains(k, ">CPU</figcaption>") || strings.Contains(k, ">Memory</figcaption>") || !strings.Contains(k, ">Network</figcaption>") {
		t.Errorf("kubernetes:\n%s", k)
	}
	if jsonOf(r["writes"]) != "0" {
		t.Errorf("an unchanged poll rewrote the markup %v times", r["writes"])
	}
}

// TestShareCSPFriendly: no inline style, no eval, every concatenated
// value through esc()/num()/a formatter or an *Html helper; colours from
// CSS classes; a legend table repeats every slice.
func TestShareCSPFriendly(t *testing.T) {
	allowed := regexp.MustCompile(`^(esc|num|[a-zA-Z]*Html)\b`)
	// A parenthesised operand on a markup line: each branch of its
	// conditional (after ? and :) is a literal, esc(), num() or *Html.
	paren := regexp.MustCompile(`\+ \(((?:[^()]|\([^()]*\))*)\)`)
	branchOK := regexp.MustCompile(`^\s*('|"|esc\(|num\(|D\.svg\(|[a-zA-Z.]*Html\b|[a-zA-Z.]*Html\()`)
	for _, f := range []string{"share.js", "donut.js"} {
		js := webAsset(t, f)
		for _, banned := range []string{"style=", ".style.", "eval(", "new Function", "setAttribute('style'", "${", "outerHTML", "insertAdjacentHTML", "document.write"} {
			if strings.Contains(js, banned) {
				t.Errorf("%s contains %q", f, banned)
			}
		}
		for i, line := range strings.Split(js, "\n") {
			// Only the lines that build markup (a string literal with '<').
			if strings.HasPrefix(strings.TrimSpace(line), "//") || !strings.Contains(line, "'<") {
				continue
			}
			for _, m := range regexp.MustCompile(`\+ ([a-z][\w$]*)`).FindAllStringSubmatch(line, -1) {
				if !allowed.MatchString(m[1]) {
					t.Errorf("%s:%d concatenates %q: %s", f, i+1, m[1], strings.TrimSpace(line))
				}
			}
			for _, m := range paren.FindAllStringSubmatch(line, -1) {
				parts := regexp.MustCompile(`\s[?:]\s`).Split(m[1], -1)
				if len(parts) < 2 {
					t.Errorf("%s:%d concatenates (%s) — not a conditional of markup: %s", f, i+1, m[1], strings.TrimSpace(line))
					continue
				}
				for _, b := range parts[1:] {
					if !branchOK.MatchString(b) {
						t.Errorf("%s:%d concatenates %q from (%s)", f, i+1, strings.TrimSpace(b), m[1])
					}
				}
			}
		}
	}
	idx := webAsset(t, "index.html")
	for i := 0; i <= 7; i++ {
		if !strings.Contains(idx, ".share-c"+jsonOf(i)+" ") {
			t.Errorf("index.html has no .share-c%d colour", i)
		}
	}
	for _, c := range []string{".share-other", ".share-free", ".share-more", ".share-track", ".share-legend"} {
		if !strings.Contains(idx, c) {
			t.Errorf("index.html lacks %s", c)
		}
	}
	for _, want := range []string{`<script src="/static/donut.js"></script>`, `<script src="/static/share.js"></script>`, `^usage(?:\/(share|apps|containers|storage))?$`} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if !strings.Contains(webAsset(t, "share.js"), "<table class=\"share-legend\">") {
		t.Error("no legend table")
	}
	u := webAsset(t, "usage.js")
	for _, want := range []string{"btnHtml('share', 'Share')", "PortcullisShare.render(", "'/api/usage?window=' + enc("} {
		if !strings.Contains(u, want) {
			t.Errorf("usage.js lacks %q", want)
		}
	}
}

// TestShareCapacityNode (review I1, M6): CPU and memory against capacity:
// with 8 CPUs, the host using 4 and an app reading 6, the slices are app
// 6, other 0, free 2 (summing to 8), the shares 75 / 0 / 25 % and a note
// that apps and core read above the host; every legend column sums to
// exactly 100 %, and a non-zero row never sits next to "100 %".
func TestShareCapacityNode(t *testing.T) {
	r := shareEval(t, `
const v = { hosts: { primary: { cpus: 8, cpu_used_cores: 4, memory_bytes: 100, mem_used_bytes: 50 } }, apps: [{ instance: 'a', name: 'A', server: 'primary', totals: { cpu_cores: 6, mem_bytes: 10 } }], core: null };
const d = D.slices(v, 'cpu', 'primary');
r.cpu = d.slices.map(s => s.key + '=' + s.value).join(' ');
r.cpuTotal = d.total;
r.cpuNote = d.note;
r.cpuShares = D.shares(d.slices.map(s => s.value), d.total);
const m = D.slices(v, 'mem', 'primary');
r.memNote = m.note;
r.thirds = D.shares([1, 1, 1], 3);
r.tiny = D.shares([996, 4], 1000);
r.tiny2 = D.shares([999, 1], 1000);
r.zeroRow = D.shares([5, 0, 5], 10);
let ok = true;
for (let n = 0; n < 200; n++) {
  const vals = Array.from({ length: 1 + (n % 7) }, (_, i) => ((n * 37 + i * 101) % 97) + 0.3 * i);
  const tot = vals.reduce((a, b) => a + b, 0);
  if (!(tot > 0)) continue;
  const sum = D.shares(vals, tot).map(x => x === '< 1 %' ? 0 : x === '> 99 %' ? 99 : parseInt(x, 10)).reduce((a, b) => a + b, 0);
  if (sum !== 100 && !D.shares(vals, tot).some(x => x === '< 1 %' || x === '> 99 %')) ok = false;
}
r.sums = ok;
`)
	want := map[string]string{
		"cpu":       `"app:a=6 other=0 free=2"`,
		"cpuTotal":  `8`,
		"cpuShares": `["75 %","0 %","25 %"]`,
		"cpuNote":   `"apps and core read above the host's own figure (samples taken at different moments)"`,
		"memNote":   `""`,
		"thirds":    `["34 %","33 %","33 %"]`,
		"tiny":      `["> 99 %","< 1 %"]`,
		"tiny2":     `["> 99 %","< 1 %"]`,
		"zeroRow":   `["50 %","0 %","50 %"]`,
		"sums":      `true`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
}

// TestShareStorageMissingNode (review M4, queued ruling): an in-total
// item without a size is a "not measured" row with its reason (never
// silently in "Other used"); a volume several apps use is the "Shared
// between apps" slice, once; images and layers go on the docker_data
// disk by its role.
func TestShareStorageMissingNode(t *testing.T) {
	r := shareEval(t, `
const st = JSON.parse(JSON.stringify(STORAGE));
st.apps[1].items.push({ kind: 'volume', target: 'b_cache', dev: 7, alloc_bytes: null, in_total: true, error: 'timed out' });
st.apps[2].items = [{ kind: 'volume', target: 'c_broken', dev: 7, alloc_bytes: null, in_total: true }];
st.apps[0].items.push({ kind: 'volume', target: 'shared_media', dev: 7, alloc_bytes: 25, in_total: false, shared_with: ['b'] });
st.apps[1].items.push({ kind: 'volume', target: 'shared_media', dev: 7, alloc_bytes: 25, in_total: false, shared_with: ['a'] });
const v = JSON.parse(JSON.stringify(VIEW)); v.apps[2].server = 'primary';
const d = D.slices(v, 'storage', 'primary', { storage: st, dev: 7 });
r.keys = d.slices.map(s => s.key + '=' + s.value).join(' ');
r.missing = d.missing;
r.sum = d.slices.reduce((a, s) => a + s.value, 0) === d.total;
const dr = D.drill(VIEW, 'a', 'storage', { storage: { apps: [{ instance: 'a', items: [{ kind: 'volume', target: 'x', alloc_bytes: null, in_total: true, partial_reason: '' }] }] } });
r.drillMissing = dr.missing;
`)
	if g := jsonOf(r["keys"]); g != `"app:a=160 app:b=40 core=60 shared=25 images=300 other=115 free=300"` {
		t.Errorf("slices %s", g)
	}
	if g := jsonOf(r["missing"]); g != `[{"label":"Beta · b_cache","why":"timed out"},{"label":"Gamma · c_broken","why":"not measured yet"}]` {
		t.Errorf("missing %s", g)
	}
	if jsonOf(r["sum"]) != "true" {
		t.Error("the storage slices don't sum to the total")
	}
	if g := jsonOf(r["drillMissing"]); g != `[{"label":"x","why":"not measured yet"}]` {
		t.Errorf("drill missing %s", g)
	}
}

// TestShareLabelsNode (review M1, M5, controller item, nit 4): reasons
// are "not measured" once; a container keeps one colour in all of the
// drill-down's donuts; disks are titled by role and path ("Docker data
// (/var/lib/docker)", "Podman data" on a Podman primary, "Shared
// folders (…)", "Portcullis data", "Disk 8:17 (/mnt/data)"); a reply for
// another window than the one picked is dropped.
func TestShareLabelsNode(t *testing.T) {
	r := shareRender(t, `
const colourOf = {};
for (const m of ['cpu', 'mem', 'io', 'net', 'storage']) {
  for (const s of window.PortcullisDonut.drill(VIEW, 'a', m, { storage: STORAGE }).slices) (colourOf[s.key] = colourOf[s.key] || new Set()).add(s.cls);
}
r.colours = Object.fromEntries(Object.entries(colourOf).map(([k, v]) => [k, [...v]]));
S.render(el, { view: VIEW, storage: STORAGE, server: 'primary', window: 'last' });
r.html = el.innerHTML;
const pod = JSON.parse(JSON.stringify(VIEW)); pod.engine = { runtime: 'podman' };
S.update(pod, STORAGE);
r.podman = el.innerHTML.indexOf('Podman data (/var/lib/docker)') >= 0;
S.act('app', 'a');
r.drill = el.innerHTML;
S.act('back');
S.act('window', '1h');
const before = el.innerHTML;
r.waiting = before.indexOf('data-share-wait') >= 0;
S.update(Object.assign({}, VIEW, { window: 'last' }), STORAGE);
r.dropped = el.innerHTML === before;
S.update(Object.assign({}, VIEW, { window: '1h' }), STORAGE);
r.taken = el.innerHTML.indexOf('data-share-wait') < 0;
`)
	var colours map[string][]string
	b, _ := json.Marshal(r["colours"])
	json.Unmarshal(b, &colours)
	for k, cs := range colours {
		if len(cs) != 1 {
			t.Errorf("%s has colours %v across the drill-down", k, cs)
		}
	}
	if colours["web.1"][0] != "share-c1" || colours["worker.1"][0] != "share-c2" || colours["shared:web.1,worker.1"][0] != "share-shared" {
		t.Errorf("drill colours %v", colours)
	}
	h, _ := r["html"].(string)
	for _, want := range []string{"Docker data (/var/lib/docker) · 1000 B", "Shared folders (/srv/media) · 500 B", "Portcullis data · 100 B", "Disk 8:17 (/mnt/data) · 100 B", "not measured: w2 is unreachable"} {
		if !strings.Contains(h, want) {
			t.Errorf("server view lacks %q", want)
		}
	}
	d, _ := r["drill"].(string)
	if strings.Contains(h+d, "not measured: not measured") || !strings.Contains(d, ">not measured: the container uses the host&#39;s network<") {
		t.Errorf("doubled or missing reason:\n%s", d)
	}
	for _, k := range []string{"podman", "waiting", "dropped", "taken"} {
		if jsonOf(r[k]) != "true" {
			t.Errorf("%s = %v", k, r[k])
		}
	}
	// Only the first donut's slices are tab stops; the legend buttons are
	// the keyboard route to every donut.
	if n := strings.Count(h, `tabindex="0"`); n == 0 || n != strings.Count(h[:strings.Index(h, ">Memory</figcaption>")], `tabindex="0"`) {
		t.Errorf("tab stops outside the first donut: %d", n)
	}
}
