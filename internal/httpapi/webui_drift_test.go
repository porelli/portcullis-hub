package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// TestDriftRenderWithErrorBox: drift items are rendered with an error
// container for inline errors.
func TestDriftRenderWithErrorBox(t *testing.T) {
	page := hubIndex(t)
	fn := hubFunc(t, page, "renderDrift")

	// Extract DRIFT_ACTIONS.
	i := strings.Index(page, "    const DRIFT_ACTIONS = {")
	if i < 0 {
		t.Fatal("the hub index lacks DRIFT_ACTIONS")
	}
	actions := page[i : i+strings.Index(page[i:], "\n    };\n")+len("\n    };\n")]

	// Extract escapeHtml.
	escapeHtml := hubFunc(t, page, "escapeHtml")

	src := escapeHtml + actions + fn + `
let driftHTML = '';
const document = {
  getElementById: () => ({
    innerHTML: '',
    classList: {
      add: () => {},
      remove: () => {}
    },
    set innerHTML(v) { driftHTML = v; }
  })
};
renderDrift({
  items: [
    { id: 'grafana', message: 'Settings changed', running: 2, total: 3, actions: ['apply', 'restart'] },
    { id: 'nextcloud', message: 'Not running', running: 0, total: 1, actions: ['start'] }
  ]
});
process.stdout.write(driftHTML);
`

	html := runNode(t, src)

	// Check that each item has data-drift-item attribute.
	if !strings.Contains(html, `data-drift-item="grafana"`) {
		t.Errorf("drift item should have data-drift-item attribute for grafana")
	}
	if !strings.Contains(html, `data-drift-item="nextcloud"`) {
		t.Errorf("drift item should have data-drift-item attribute for nextcloud")
	}

	// Check that each item has an error box.
	errorBoxPattern := regexp.MustCompile(`<div class="drift-error" data-drift-error hidden></div>`)
	matches := errorBoxPattern.FindAllString(html, -1)
	if len(matches) != 2 {
		t.Errorf("expected 2 error boxes, found %d in HTML: %s", len(matches), html)
	}
}

// TestDriftResolveBusyState: resolveDrift function structure checks (can't
// fully test async DOM updates without a browser, but we can check the code
// structure).
func TestDriftResolveBusyState(t *testing.T) {
	page := hubIndex(t)
	fn := hubFunc(t, page, "resolveDrift")

	// Check that resolveDrift prevents double submit.
	if !strings.Contains(fn, "if (item.dataset.busy) return;") {
		t.Errorf("resolveDrift should check item.dataset.busy to prevent double submit")
	}

	// Check that it sets busy flag.
	if !strings.Contains(fn, `item.dataset.busy = '1';`) {
		t.Errorf("resolveDrift should set item.dataset.busy")
	}

	// Check that it disables all buttons.
	if !strings.Contains(fn, "buttons.forEach") && !strings.Contains(fn, "disabled = true") {
		t.Errorf("resolveDrift should disable all buttons in the item")
	}

	// Check that it shows busy text.
	if !strings.Contains(fn, "Applying…") || !strings.Contains(fn, "Disabling…") {
		t.Errorf("resolveDrift should show busy text (Applying… / Disabling…)")
	}

	// Check that it clears busy state on error.
	if !strings.Contains(fn, "delete item.dataset.busy") {
		t.Errorf("resolveDrift should clear item.dataset.busy on error")
	}

	// Check that it re-enables buttons on error.
	if !strings.Contains(fn, "disabled = false") {
		t.Errorf("resolveDrift should re-enable buttons on error")
	}

	// Check that it shows error inline.
	if !strings.Contains(fn, "errBox.textContent = e.message") {
		t.Errorf("resolveDrift should show error inline in errBox")
	}

	// Check that it unhides error box on error.
	if !strings.Contains(fn, "errBox.hidden = false") {
		t.Errorf("resolveDrift should unhide error box on error")
	}
}
