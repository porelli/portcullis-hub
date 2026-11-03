// Portcullis Hub settings panel (Task 14, contract §13).
// Usage: window.PortcullisSettings.render(container, instanceId)
// Consumes GET /api/instances/{id}/settings, PUT /api/instances/{id}/settings,
// POST .../settings/preview, POST .../settings/retry.

(function() {
  'use strict';

  // Escape HTML (shared escapeHtml from index.html).
  const esc = window.escapeHtml || (s => String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])));

  let panelData = null;  // Current panel response from API
  let draftData = null;  // Current draft (edited values)
  let previewData = null; // Last preview result
  let previewTimer = null; // Debounce timer for preview
  let saveInProgress = false;

  // ── Utilities ───────────────────────────────────────────────────

  // Size units for rendering
  const SIZE_UNITS = ['MiB', 'GiB', 'TiB'];

  // Parse a size value into {num, unit, unlimited}
  function parseSize(bytes) {
    if (bytes === 'unlimited') return { unlimited: true };
    if (typeof bytes !== 'number') return { num: '', unit: 'GiB', unlimited: false };

    // Convert bytes to best unit
    const tib = bytes / (1024 * 1024 * 1024 * 1024);
    if (tib >= 1) return { num: tib, unit: 'TiB', unlimited: false };
    const gib = bytes / (1024 * 1024 * 1024);
    if (gib >= 1) return { num: gib, unit: 'GiB', unlimited: false };
    const mib = bytes / (1024 * 1024);
    return { num: mib, unit: 'MiB', unlimited: false };
  }

  // Render a size value for display
  function displaySize(bytes) {
    if (bytes === 'unlimited') return 'unlimited';
    const s = parseSize(bytes);
    if (s.unlimited) return 'unlimited';
    return s.num + ' ' + s.unit;
  }

  // Display a resolved value (from preview)
  function displayResolved(option, resolved) {
    if (!resolved.value) return 'unresolved: the app\'s own default applies';
    if (option.type === 'size') return displaySize(resolved.value);
    if (Array.isArray(resolved.value)) return resolved.value.join(', ');
    return String(resolved.value);
  }

  // Get current draft or fall back to panel data
  function currentDraft() {
    return draftData || {};
  }

  // Mark draft as changed
  function setDraft(key, value) {
    if (!draftData) draftData = {};
    draftData[key] = value;
    requestPreview();
  }

  // ── Preview (debounced) ─────────────────────────────────────────

  function requestPreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 400);
  }

  async function runPreview() {
    if (!panelData) return;
    const body = buildSaveBody();
    try {
      // Use the global apiPost helper (proxy secret handled by middleware)
      if (window.apiPost) {
        previewData = await window.apiPost('/api/instances/' + encodeURIComponent(panelData.id) + '/settings/preview', body);
      } else {
        const res = await fetch('/api/instances/' + encodeURIComponent(panelData.id) + '/settings/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error(await res.text());
        previewData = await res.json();
      }
      renderSaveBar();
      renderPreviews();
    } catch (err) {
      console.error('Preview failed:', err);
    }
  }

  // ── Build save body ─────────────────────────────────────────────

  function buildSaveBody() {
    const body = {
      values: {},
      person: {},
      groups: {},
      secrets: {},
      ports: {}
    };

    // Collect instance values
    const draft = currentDraft();
    for (const opt of panelData.options || []) {
      if (opt.scope === 'instance' && opt.type !== 'secret') {
        const key = opt.key;
        if (key in draft.values) {
          body.values[key] = draft.values[key];
        } else if (panelData.instance && key in panelData.instance) {
          body.values[key] = panelData.instance[key];
        }
      }
    }

    // Person configurations
    if (draft.person) {
      for (const [key, pc] of Object.entries(draft.person)) {
        body.person[key] = pc;
      }
    } else if (panelData.person) {
      for (const [key, pc] of Object.entries(panelData.person)) {
        body.person[key] = pc;
      }
    }

    // Group records
    if (draft.groups) {
      for (const [key, recs] of Object.entries(draft.groups)) {
        body.groups[key] = recs;
      }
    } else if (panelData.groups) {
      for (const [key, recs] of Object.entries(panelData.groups)) {
        body.groups[key] = recs;
      }
    }

    // Secrets (only changed ones from UI)
    if (draft.secrets) {
      body.secrets = draft.secrets;
    }

    // Ports
    if (draft.ports) {
      for (const [key, val] of Object.entries(draft.ports)) {
        body.ports[key] = val;
      }
    } else if (panelData.ports) {
      for (const [key, val] of Object.entries(panelData.ports)) {
        body.ports[key] = val;
      }
    }

    return body;
  }

  // ── Render functions ────────────────────────────────────────────

  function render(container, instanceId) {
    container.innerHTML = '<p class="settings-empty">Loading settings...</p>';

    // Use the global apiGet helper if available
    const loadData = window.apiGet ?
      window.apiGet('/api/instances/' + encodeURIComponent(instanceId) + '/settings') :
      fetch('/api/instances/' + encodeURIComponent(instanceId) + '/settings')
        .then(res => {
          if (!res.ok) throw new Error('Failed to load settings');
          return res.json();
        });

    loadData
      .then(data => {
        panelData = data;
        draftData = null;
        previewData = null;
        renderPanel(container);
        requestPreview();
      })
      .catch(err => {
        container.innerHTML = '<p class="settings-empty">Failed to load settings: ' + esc(err.message) + '</p>';
      });
  }

  function renderPanel(container) {
    let html = '<div class="settings-panel">';

    // Deliveries strip
    html += renderDeliveries();

    // Render sections
    const sections = panelData.sections || [];
    if (sections.length === 0) {
      // No sections: render all options
      html += renderOptions(panelData.options || []);
    } else {
      for (const section of sections) {
        const opts = (panelData.options || []).filter(o => o.section === section);
        if (opts.length === 0) continue;
        html += '<div class="settings-section">';
        html += '<h3 class="section-title">' + esc(section) + '</h3>';
        html += renderOptions(opts);
        html += '</div>';
      }
    }

    // Save bar
    html += '<div id="settings-save-bar"></div>';

    html += '</div>';
    container.innerHTML = html;
    attachListeners(container);
  }

  function renderDeliveries() {
    const d = panelData.deliveries;
    if (!d || !d.units || d.units.length === 0) return '';

    let html = '<div class="deliveries-strip">';
    html += '<div class="delivery-title">Deliveries</div>';
    html += '<div class="delivery-units">';

    for (const u of d.units) {
      const hasError = u.error && u.error !== '';
      const skipped = u.skipped && u.skipped !== '';
      let statusClass = hasError ? 'delivery-failed' : (skipped ? 'delivery-skipped' : 'delivery-ok');
      let statusText = hasError ? u.error : (skipped ? u.skipped : 'applied');

      html += '<div class="delivery-unit ' + statusClass + '">';
      html += '<span class="delivery-name">' + esc(u.name) + '</span>';
      html += '<span class="delivery-status">' + esc(statusText) + '</span>';
      html += '</div>';
    }

    html += '</div>';
    html += '<button type="button" class="btn btn-sm btn-secondary" data-retry-deliveries="1">Retry</button>';
    html += '</div>';

    return html;
  }

  function renderOptions(options) {
    let html = '';

    for (const opt of options) {
      html += '<div class="option-row" data-option-key="' + esc(opt.key) + '">';
      html += '<div class="option-header">';
      html += '<label class="option-label">' + esc(opt.label) + '</label>';
      html += '<span class="option-applies">' + esc(opt.effect) + '</span>';
      html += '</div>';

      if (opt.description) {
        html += '<div class="option-description">' + esc(opt.description) + '</div>';
      }

      if (opt.warnings && opt.warnings.length > 0) {
        for (const w of opt.warnings) {
          html += '<div class="option-warning">' + esc(w) + '</div>';
        }
      }

      // Render based on scope
      if (opt.scope === 'person') {
        html += renderPersonOption(opt);
      } else if (opt.scope === 'group') {
        html += renderGroupOption(opt);
      } else {
        html += renderInstanceOption(opt);
      }

      html += '</div>';
    }

    return html;
  }

  function renderInstanceOption(opt) {
    const draft = currentDraft();
    let value = (draft.values && opt.key in draft.values) ? draft.values[opt.key] :
                (panelData.instance && opt.key in panelData.instance) ? panelData.instance[opt.key] :
                opt.default;

    if (opt.type === 'secret') {
      return renderSecretOption(opt);
    }

    if (opt.type === 'size') {
      return renderSizeOption(opt, value);
    }

    if (opt.type === 'bool') {
      const checked = value === true || value === 'true';
      return '<label class="option-checkbox"><input type="checkbox" data-instance-value="' + esc(opt.key) + '" ' + (checked ? 'checked' : '') + '> ' + esc(opt.label) + '</label>';
    }

    if (opt.type === 'enum') {
      let html = '<select data-instance-value="' + esc(opt.key) + '">';
      for (const o of opt.options || []) {
        const sel = value === o.value ? ' selected' : '';
        html += '<option value="' + esc(o.value) + '"' + sel + '>' + esc(o.label || o.value) + '</option>';
      }
      html += '</select>';
      return html;
    }

    if (opt.type === 'path') {
      let html = '<input type="text" data-instance-value="' + esc(opt.key) + '" value="' + esc(value || '') + '" placeholder="/path/on/host">';
      if (opt.writes_as) {
        html += '<small class="option-hint">The app writes here as ' + esc(opt.writes_as.uid) + ':' + esc(opt.writes_as.gid) + '</small>';
      }
      return html;
    }

    // Default: text input
    return '<input type="text" data-instance-value="' + esc(opt.key) + '" value="' + esc(value || '') + '">';
  }

  function renderSecretOption(opt) {
    const secret = panelData.secrets && panelData.secrets[opt.key];
    let html = '<div class="secret-option">';

    if (secret && secret.set) {
      html += '<div class="secret-status">Set ✓ (updated ' + esc(new Date(secret.updated_at).toLocaleDateString()) + ')</div>';
      html += '<div class="secret-actions">';
      html += '<button type="button" class="btn btn-sm" data-secret-replace="' + esc(opt.key) + '">Replace</button>';
      if (opt.generate) {
        html += '<button type="button" class="btn btn-sm" data-secret-generate="' + esc(opt.key) + '">Generate</button>';
      }
      html += '<button type="button" class="btn btn-sm btn-danger" data-secret-clear="' + esc(opt.key) + '">Clear</button>';
      html += '</div>';
    } else {
      html += '<div class="secret-actions">';
      html += '<input type="password" data-secret-value="' + esc(opt.key) + '" placeholder="Enter secret value">';
      if (opt.generate) {
        html += '<button type="button" class="btn btn-sm" data-secret-generate="' + esc(opt.key) + '">Generate</button>';
      }
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  function renderSizeOption(opt, value) {
    const parsed = parseSize(value);
    let html = '<div class="size-option">';
    html += '<input type="number" data-size-value="' + esc(opt.key) + '" value="' + (parsed.unlimited ? '' : parsed.num) + '" step="' + (opt.step || 1) + '">';
    html += '<select data-size-unit="' + esc(opt.key) + '">';
    for (const u of SIZE_UNITS) {
      const sel = parsed.unit === u ? ' selected' : '';
      html += '<option value="' + esc(u) + '"' + sel + '>' + esc(u) + '</option>';
    }
    html += '</select>';
    if (opt.allow_unlimited) {
      html += '<label class="option-checkbox"><input type="checkbox" data-size-unlimited="' + esc(opt.key) + '" ' + (parsed.unlimited ? 'checked' : '') + '> unlimited</label>';
    }
    html += '</div>';
    return html;
  }

  function renderPersonOption(opt) {
    const draft = currentDraft();
    const pc = (draft.person && draft.person[opt.key]) || panelData.person[opt.key] || { default: opt.default, resolve: opt.resolve, rows: [] };

    let html = '<div class="person-option" data-person-key="' + esc(opt.key) + '">';

    // Default row
    html += '<div class="person-row person-row-default">';
    html += '<span class="person-row-label">Everyone else with access</span>';
    html += renderPersonValue(opt, pc.default);
    html += '</div>';

    // Group rows
    for (let i = 0; i < pc.rows.length; i++) {
      const row = pc.rows[i];
      html += '<div class="person-row" data-row-index="' + i + '">';
      html += renderGroupPicker(opt, row.group, row.group_id);
      html += renderPersonValue(opt, row.value);
      html += '<button type="button" class="btn-icon" data-remove-row="' + i + '">✕</button>';
      html += '</div>';
    }

    // Add group button
    html += '<div class="person-row-add">';
    html += '<button type="button" class="btn btn-sm" data-add-group-row="' + esc(opt.key) + '">+ Add group</button>';
    html += '</div>';

    // Resolve selector
    if (opt.resolve_choices && opt.resolve_choices.length > 1) {
      html += '<div class="person-resolve">';
      html += '<label>When someone is in several groups: </label>';
      html += '<select data-person-resolve="' + esc(opt.key) + '">';
      for (const choice of opt.resolve_choices) {
        const sel = pc.resolve === choice ? ' selected' : '';
        html += '<option value="' + esc(choice) + '"' + sel + '>' + esc(choice) + '</option>';
      }
      html += '</select>';
      html += '</div>';
    }

    // Preview
    html += '<div class="person-preview" data-preview-key="' + esc(opt.key) + '"></div>';

    html += '</div>';
    return html;
  }

  function renderGroupPicker(opt, groupName, groupId) {
    let html = '<select data-group-name="1" data-group-id="' + (groupId || '') + '">';

    if (opt.privileged && opt.group_choices) {
      for (const gc of opt.group_choices) {
        const sel = gc.name === groupName ? ' selected' : '';
        const disabled = gc.disabled ? ' disabled' : '';
        html += '<option value="' + esc(gc.name) + '"' + sel + disabled;
        if (gc.reason) html += ' title="' + esc(gc.reason) + '"';
        html += '>' + esc(gc.name);
        if (gc.reason) html += ' (' + esc(gc.reason) + ')';
        html += '</option>';
      }
    } else {
      // TODO: Load available groups from directory API
      html += '<option value="' + esc(groupName) + '" selected>' + esc(groupName) + '</option>';
    }

    html += '</select>';
    return html;
  }

  function renderPersonValue(opt, value) {
    // Render input for the value based on option type
    if (opt.type === 'size') {
      return renderSizeOption(opt, value);
    }

    if (opt.type === 'bool') {
      const checked = value === true || value === 'true';
      return '<input type="checkbox" data-person-value="1" ' + (checked ? 'checked' : '') + '>';
    }

    if (opt.type === 'enum') {
      let html = '<select data-person-value="1">';
      for (const o of opt.options || []) {
        const sel = value === o.value ? ' selected' : '';
        html += '<option value="' + esc(o.value) + '"' + sel + '>' + esc(o.label || o.value) + '</option>';
      }
      html += '</select>';
      return html;
    }

    return '<input type="text" data-person-value="1" value="' + esc(value || '') + '">';
  }

  function renderGroupOption(opt) {
    // Group-scope options (not implemented in Task 14)
    return '<div class="option-note">Group-scope options are not yet implemented.</div>';
  }

  function renderPreviews() {
    if (!previewData || !previewData.options) return;

    for (const [key, preview] of Object.entries(previewData.options)) {
      const container = document.querySelector('[data-preview-key="' + CSS.escape(key) + '"]');
      if (!container) continue;

      let html = '<div class="preview-header">';
      html += '<strong>Who gets what (' + preview.people.length + ' people with access)</strong>';
      if (preview.changes > 0) {
        html += ' <span class="preview-changes">' + preview.changes + ' change' + (preview.changes === 1 ? '' : 's') + '</span>';
      }
      html += '</div>';

      // Show first 50 people
      html += '<div class="preview-list">';
      const shown = preview.people.slice(0, 50);
      for (const p of shown) {
        html += '<div class="preview-row">';
        html += '<span class="preview-user">' + esc(p.user) + '</span>';
        html += '<span class="preview-value">' + esc(p.display) + '</span>';
        if (p.reason && p.reason.group) {
          html += '<span class="preview-reason">from ' + esc(p.reason.group) + '</span>';
        }
        html += '</div>';
      }
      html += '</div>';

      if (preview.people.length > 50) {
        html += '<div class="preview-more">' + (preview.people.length - 50) + ' more...</div>';
      }

      // No access warnings
      if (preview.no_access) {
        for (const [group, count] of Object.entries(preview.no_access)) {
          if (count > 0) {
            html += '<div class="preview-warning">⚠ ' + count + ' member' + (count === 1 ? '' : 's') + ' of ' + esc(group) + ' ' + (count === 1 ? 'has' : 'have') + ' no access to this instance and get' + (count === 1 ? 's' : '') + ' nothing.</div>';
          }
        }
      }

      container.innerHTML = html;
    }
  }

  function renderSaveBar() {
    const container = document.getElementById('settings-save-bar');
    if (!container) return;

    let html = '<div class="save-bar">';

    if (previewData) {
      html += '<div class="save-effect">';
      if (previewData.effect && previewData.effect !== 'none') {
        html += 'Saving ' + esc(previewData.effect === 'restart' ? 'restarts ' + panelData.name : previewData.effect);
      } else {
        html += 'Takes effect with no restart';
      }
      html += '</div>';

      // Count changes
      let totalChanges = 0;
      if (previewData.options) {
        for (const preview of Object.values(previewData.options)) {
          totalChanges += preview.changes || 0;
        }
      }

      if (totalChanges > 0) {
        html += '<div class="save-changes">Changes: ' + totalChanges + ' people get a new value</div>';
      }
    }

    html += '<button type="button" class="btn btn-primary" data-save-settings="1"' + (saveInProgress ? ' disabled' : '') + '>';
    html += saveInProgress ? 'Saving...' : 'Save';
    html += '</button>';
    html += '</div>';

    container.innerHTML = html;
  }

  // ── Event handlers ──────────────────────────────────────────────

  function attachListeners(container) {
    container.addEventListener('click', handleClick);
    container.addEventListener('input', handleInput);
    container.addEventListener('change', handleChange);
  }

  function handleClick(e) {
    const t = e.target;

    if (t.closest('[data-save-settings]')) {
      saveSettings();
      return;
    }

    if (t.closest('[data-retry-deliveries]')) {
      retryDeliveries();
      return;
    }

    const addGroupRow = t.closest('[data-add-group-row]');
    if (addGroupRow) {
      const key = addGroupRow.dataset.addGroupRow;
      addGroupRow_handler(key);
      return;
    }

    const removeRow = t.closest('[data-remove-row]');
    if (removeRow) {
      const personOpt = removeRow.closest('[data-person-key]');
      if (personOpt) {
        const key = personOpt.dataset.personKey;
        const index = parseInt(removeRow.dataset.removeRow, 10);
        removeGroupRow(key, index);
      }
      return;
    }

    const secretReplace = t.closest('[data-secret-replace]');
    if (secretReplace) {
      showSecretInput(secretReplace.dataset.secretReplace);
      return;
    }

    const secretGenerate = t.closest('[data-secret-generate]');
    if (secretGenerate) {
      generateSecret(secretGenerate.dataset.secretGenerate);
      return;
    }

    const secretClear = t.closest('[data-secret-clear]');
    if (secretClear) {
      if (confirm('Clear this secret? The app will receive an empty value.')) {
        clearSecret(secretClear.dataset.secretClear);
      }
      return;
    }
  }

  function handleInput(e) {
    const t = e.target;

    const instanceValue = t.closest('[data-instance-value]');
    if (instanceValue) {
      const key = instanceValue.dataset.instanceValue;
      updateInstanceValue(key, t.value);
      return;
    }

    const sizeValue = t.closest('[data-size-value]');
    if (sizeValue) {
      const key = sizeValue.dataset.sizeValue;
      updateSizeValue(key);
      return;
    }
  }

  function handleChange(e) {
    const t = e.target;

    const personResolve = t.closest('[data-person-resolve]');
    if (personResolve) {
      const key = personResolve.dataset.personResolve;
      updatePersonResolve(key, t.value);
      return;
    }

    const sizeUnit = t.closest('[data-size-unit]');
    if (sizeUnit) {
      const key = sizeUnit.dataset.sizeUnit;
      updateSizeValue(key);
      return;
    }

    const sizeUnlimited = t.closest('[data-size-unlimited]');
    if (sizeUnlimited) {
      const key = sizeUnlimited.dataset.sizeUnlimited;
      updateSizeValue(key);
      return;
    }
  }

  function updateInstanceValue(key, value) {
    if (!draftData) draftData = { values: {} };
    if (!draftData.values) draftData.values = {};
    draftData.values[key] = value;
    requestPreview();
  }

  function updateSizeValue(key) {
    const container = document.querySelector('[data-size-value="' + CSS.escape(key) + '"]').closest('.size-option');
    const numInput = container.querySelector('[data-size-value]');
    const unitSelect = container.querySelector('[data-size-unit]');
    const unlimitedCheck = container.querySelector('[data-size-unlimited]');

    if (unlimitedCheck && unlimitedCheck.checked) {
      if (!draftData) draftData = { values: {} };
      if (!draftData.values) draftData.values = {};
      draftData.values[key] = 'unlimited';
    } else {
      const num = parseFloat(numInput.value);
      const unit = unitSelect.value;
      let bytes;
      if (unit === 'TiB') bytes = num * 1024 * 1024 * 1024 * 1024;
      else if (unit === 'GiB') bytes = num * 1024 * 1024 * 1024;
      else bytes = num * 1024 * 1024;

      if (!draftData) draftData = { values: {} };
      if (!draftData.values) draftData.values = {};
      draftData.values[key] = bytes;
    }
    requestPreview();
  }

  function updatePersonResolve(key, resolve) {
    if (!draftData) draftData = { person: {} };
    if (!draftData.person) draftData.person = {};
    if (!draftData.person[key]) {
      draftData.person[key] = JSON.parse(JSON.stringify(panelData.person[key] || {}));
    }
    draftData.person[key].resolve = resolve;
    requestPreview();
  }

  function addGroupRow_handler(key) {
    if (!draftData) draftData = { person: {} };
    if (!draftData.person) draftData.person = {};
    if (!draftData.person[key]) {
      draftData.person[key] = JSON.parse(JSON.stringify(panelData.person[key] || { rows: [] }));
    }
    draftData.person[key].rows.push({ group: '', value: null });

    // Re-render the person option
    const container = document.querySelector('[data-person-key="' + CSS.escape(key) + '"]');
    if (container) {
      const opt = panelData.options.find(o => o.key === key);
      if (opt) {
        container.outerHTML = '<div class="option-row" data-option-key="' + esc(opt.key) + '">' + renderPersonOption(opt) + '</div>';
      }
    }
  }

  function removeGroupRow(key, index) {
    if (!draftData) draftData = { person: {} };
    if (!draftData.person) draftData.person = {};
    if (!draftData.person[key]) {
      draftData.person[key] = JSON.parse(JSON.stringify(panelData.person[key] || { rows: [] }));
    }
    draftData.person[key].rows.splice(index, 1);

    // Re-render the person option
    const container = document.querySelector('[data-person-key="' + CSS.escape(key) + '"]');
    if (container) {
      const opt = panelData.options.find(o => o.key === key);
      if (opt) {
        container.outerHTML = '<div class="option-row" data-option-key="' + esc(opt.key) + '">' + renderPersonOption(opt) + '</div>';
      }
    }
    requestPreview();
  }

  function showSecretInput(key) {
    // Replace the "Set ✓" status with an input
    const secretOpt = document.querySelector('[data-option-key="' + CSS.escape(key) + '"] .secret-option');
    if (!secretOpt) return;

    secretOpt.innerHTML = '<div class="secret-actions">' +
      '<input type="password" data-secret-value="' + esc(key) + '" placeholder="Enter new secret value">' +
      '<button type="button" class="btn btn-sm" data-secret-save="' + esc(key) + '">Save</button>' +
      '</div>';
  }

  function generateSecret(key) {
    // Mark as generate in draft
    if (!draftData) draftData = { secrets: {} };
    if (!draftData.secrets) draftData.secrets = {};
    draftData.secrets[key] = { generate: true };
    requestPreview();
  }

  function clearSecret(key) {
    // Mark as clear in draft
    if (!draftData) draftData = { secrets: {} };
    if (!draftData.secrets) draftData.secrets = {};
    draftData.secrets[key] = { clear: true };
    requestPreview();
  }

  async function saveSettings() {
    if (saveInProgress) return;
    saveInProgress = true;
    renderSaveBar();

    const body = buildSaveBody();

    try {
      // Use the global apiPut helper if available
      if (window.apiPut) {
        await window.apiPut('/api/instances/' + encodeURIComponent(panelData.id) + '/settings', body);
      } else {
        const res = await fetch('/api/instances/' + encodeURIComponent(panelData.id) + '/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!res.ok) {
          const err = await res.text();
          throw new Error(err);
        }
      }

      // Clear secrets from inputs
      document.querySelectorAll('[data-secret-value]').forEach(inp => inp.value = '');

      // Show success
      if (window.showToast) {
        window.showToast('Settings saved', 'success');
      }

      // Reload panel
      const container = document.querySelector('.settings-panel').parentElement;
      render(container, panelData.id);

    } catch (err) {
      console.error('Save failed:', err);
      if (window.showToast) {
        window.showToast('Failed to save: ' + err.message, 'error');
      }
    } finally {
      saveInProgress = false;
      renderSaveBar();
    }
  }

  async function retryDeliveries() {
    try {
      // Use the global apiPost helper if available (needs Content-Type: application/json per brief)
      if (window.apiPost) {
        await window.apiPost('/api/instances/' + encodeURIComponent(panelData.id) + '/settings/retry', {});
      } else {
        const res = await fetch('/api/instances/' + encodeURIComponent(panelData.id) + '/settings/retry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}'
        });
        if (!res.ok) {
          throw new Error(await res.text());
        }
      }

      if (window.showToast) {
        window.showToast('Deliveries retried', 'success');
      }

      // Reload deliveries status
      setTimeout(() => {
        const container = document.querySelector('.settings-panel').parentElement;
        render(container, panelData.id);
      }, 1000);

    } catch (err) {
      console.error('Retry failed:', err);
      if (window.showToast) {
        window.showToast('Retry failed: ' + err.message, 'error');
      }
    }
  }

  // ── Export ──────────────────────────────────────────────────────

  window.PortcullisSettings = {
    render: render
  };

})();
