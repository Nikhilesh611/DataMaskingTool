// Enterprise Admin Control Plane JavaScript Application

document.addEventListener('DOMContentLoaded', () => {

  // ── State Management ─────────────────────────────────────────────────────────
  const STORAGE_KEY = 'admin_session_token';

  function getToken() {
    return sessionStorage.getItem(STORAGE_KEY);
  }

  function setToken(token) {
    sessionStorage.setItem(STORAGE_KEY, token);
  }

  function clearToken() {
    sessionStorage.removeItem(STORAGE_KEY);
  }

  async function apiFetch(url, options = {}) {
    const token = getToken();
    const headers = options.headers || {};

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    options.headers = headers;
    const response = await fetch(url, options);

    if (response.status === 401) {
      clearToken();
      showLoginView('Session expired. Please log in again.');
      throw new Error('Unauthorized');
    }

    const data = await response.json();
    if (!response.ok) {
      const msg = (data.detail && typeof data.detail === 'string')
        ? data.detail
        : (data.detail?.message || 'API Error');
      throw new Error(msg);
    }

    return data;
  }

  // ── Views & Tabs ─────────────────────────────────────────────────────────────
  const loginView = document.getElementById('login-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginError = document.getElementById('login-error');

  function showLoginView(errorMsg = '') {
    dashboardView.classList.add('hidden');
    loginView.classList.remove('hidden');
    if (errorMsg) {
      loginError.textContent = errorMsg;
      loginError.classList.remove('hidden');
    } else {
      loginError.classList.add('hidden');
    }
  }

  function showDashboardView() {
    loginView.classList.add('hidden');
    dashboardView.classList.remove('hidden');
    loadMappings();
    loadPolicy();
  }

  // Check initial login state
  if (getToken()) {
    showDashboardView();
  } else {
    showLoginView();
  }

  // Login Form Submission
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();

    try {
      const res = await fetch('/api/v1/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Invalid username or password.');

      setToken(data.token);
      showDashboardView();
    } catch (err) {
      loginError.textContent = err.message;
      loginError.classList.remove('hidden');
    }
  });

  // Logout Button
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
      await apiFetch('/api/v1/admin/logout', { method: 'POST' });
    } catch (_) {}
    clearToken();
    showLoginView();
  });

  // Tab Navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetTab = document.getElementById(btn.getAttribute('data-tab'));
      if (targetTab) targetTab.classList.add('active');
    });
  });


  // ── Tab 1: Group Mappings ─────────────────────────────────────────────────────
  const mappingsTableBody = document.getElementById('mappings-table-body');
  const mappingModal = document.getElementById('mapping-modal');
  const mappingForm = document.getElementById('mapping-form');

  async function loadMappings() {
    try {
      const data = await apiFetch('/api/v1/admin/mappings');
      mappingsTableBody.innerHTML = '';

      if (!data.mappings || data.mappings.length === 0) {
        mappingsTableBody.innerHTML = '<tr><td colspan="4" class="text-muted">No group mappings configured. Click "Add New Mapping" above.</td></tr>';
        return;
      }

      data.mappings.forEach(m => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(m.group)}</strong></td>
          <td><span class="badge badge-admin">${escapeHtml(m.internal_role)}</span></td>
          <td>Priority ${m.priority}</td>
          <td>
            <button class="btn btn-outline btn-sm edit-mapping-btn" data-group="${escapeHtml(m.group)}" data-role="${escapeHtml(m.internal_role)}" data-priority="${m.priority}">Edit</button>
            <button class="btn btn-danger btn-sm delete-mapping-btn" data-group="${escapeHtml(m.group)}">Delete</button>
          </td>
        `;
        mappingsTableBody.appendChild(tr);
      });

      // Attach event listeners for delete and edit
      document.querySelectorAll('.delete-mapping-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteMapping(btn.getAttribute('data-group')));
      });
      document.querySelectorAll('.edit-mapping-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openMappingModal(
            btn.getAttribute('data-group'),
            btn.getAttribute('data-role'),
            btn.getAttribute('data-priority')
          );
        });
      });

    } catch (err) {
      mappingsTableBody.innerHTML = `<tr><td colspan="4" class="alert alert-error">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function deleteMapping(group) {
    if (!confirm(`Are you sure you want to delete mapping for group "${group}"?`)) return;
    try {
      await apiFetch(`/api/v1/admin/mappings/${encodeURIComponent(group)}`, { method: 'DELETE' });
      loadMappings();
    } catch (err) {
      alert(`Failed to delete mapping: ${err.message}`);
    }
  }

  function openMappingModal(group = '', role = '', priority = 10) {
    document.getElementById('modal-title').textContent = group ? 'Edit Group Mapping' : 'Add Group Mapping';
    document.getElementById('map-group-name').value = group;
    document.getElementById('map-role-name').value = role;
    document.getElementById('map-priority').value = priority;
    mappingModal.classList.remove('hidden');
  }

  document.getElementById('add-mapping-btn').addEventListener('click', () => openMappingModal());
  document.getElementById('close-modal-btn').addEventListener('click', () => mappingModal.classList.add('hidden'));

  mappingForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const group = document.getElementById('map-group-name').value.trim();
    const internal_role = document.getElementById('map-role-name').value.trim();
    const priority = parseInt(document.getElementById('map-priority').value, 10);

    try {
      await apiFetch('/api/v1/admin/mappings', {
        method: 'POST',
        body: JSON.stringify({ group, internal_role, priority })
      });
      mappingModal.classList.add('hidden');
      loadMappings();
    } catch (err) {
      alert(`Error saving mapping: ${err.message}`);
    }
  });

  // Simulator
  document.getElementById('run-sim-btn').addEventListener('click', async () => {
    const rawInput = document.getElementById('sim-groups-input').value.trim();
    const groups = rawInput.split(',').map(g => g.trim()).filter(Boolean);
    const resultBox = document.getElementById('sim-result-box');

    if (groups.length === 0) {
      resultBox.textContent = 'Please enter at least one group name.';
      return;
    }

    try {
      const data = await apiFetch('/api/v1/admin/simulate-resolution', {
        method: 'POST',
        body: JSON.stringify({ groups })
      });

      if (data.match_found) {
        resultBox.textContent = `✅ RESOLVED ROLE: "${data.resolved_role}"\n\nPriority Evaluation Chain:\n` +
          data.evaluations.map(e => `  [${e.is_winner ? 'WINNER' : e.in_user_claims ? 'MATCH' : 'SKIP'}] Group: "${e.group}" -> Role: "${e.internal_role}" (Priority: ${e.priority})`).join('\n');
      } else {
        resultBox.textContent = `❌ FAIL-CLOSED (403 Forbidden)\nNo input group matched any active mapping.`;
      }
    } catch (err) {
      resultBox.textContent = `Error: ${err.message}`;
    }
  });


  // ── Tab 2: Policy Management ─────────────────────────────────────────────────
  const policyEditor = document.getElementById('policy-yaml-editor');
  const policyAlert = document.getElementById('policy-alert');
  const policyStatusBadge = document.getElementById('policy-status-badge');

  async function loadPolicy() {
    try {
      const data = await apiFetch('/api/v1/admin/policy');
      policyEditor.value = data.yaml_content || '';
      policyStatusBadge.textContent = 'Valid';
      policyStatusBadge.className = 'badge badge-success';
    } catch (err) {
      policyAlert.textContent = `Failed to load policy: ${err.message}`;
      policyAlert.className = 'alert alert-error mt-3';
      policyAlert.classList.remove('hidden');
    }
  }

  document.getElementById('save-policy-btn').addEventListener('click', async () => {
    policyAlert.classList.add('hidden');
    const yaml_content = policyEditor.value;

    try {
      const data = await apiFetch('/api/v1/admin/policy', {
        method: 'PUT',
        body: JSON.stringify({ yaml_content })
      });

      policyStatusBadge.textContent = 'Valid & Saved';
      policyStatusBadge.className = 'badge badge-success';
      policyAlert.textContent = 'Policy validated, saved to disk, and hot-reloaded successfully!';
      policyAlert.className = 'alert alert-success mt-3';
      policyAlert.classList.remove('hidden');
    } catch (err) {
      policyStatusBadge.textContent = 'Validation Error';
      policyStatusBadge.className = 'badge badge-admin';
      policyAlert.textContent = `Policy Validation Failed: ${err.message}`;
      policyAlert.className = 'alert alert-error mt-3';
      policyAlert.classList.remove('hidden');
    }
  });


  // ── Tab 3: Masking Sandbox ──────────────────────────────────────────────────
  document.getElementById('run-sandbox-btn').addEventListener('click', async () => {
    const role = document.getElementById('sandbox-role-select').value;
    const format = document.getElementById('sandbox-format-select').value;
    const inputStr = document.getElementById('sandbox-input').value.trim();
    const outputBox = document.getElementById('sandbox-output');
    const metricsBadge = document.getElementById('sandbox-metrics-badge');

    let payload;
    try {
      payload = format === 'json' ? JSON.parse(inputStr) : inputStr;
    } catch (e) {
      outputBox.textContent = `JSON Parsing Error: ${e.message}`;
      return;
    }

    try {
      const data = await apiFetch('/api/v1/admin/sandbox', {
        method: 'POST',
        body: JSON.stringify({ payload, role, format })
      });

      outputBox.textContent = typeof data.masked_output === 'object'
        ? JSON.stringify(data.masked_output, null, 2)
        : data.masked_output;

      metricsBadge.textContent = `Evaluated: ${data.metrics.scopes_evaluated} | Dropped: ${data.metrics.scopes_dropped} | Profiles: ${data.metrics.profiles_applied.join(', ') || 'None'}`;
      metricsBadge.classList.remove('hidden');
    } catch (err) {
      outputBox.textContent = `Sandbox Error: ${err.message}`;
      metricsBadge.classList.add('hidden');
    }
  });


  // Utility
  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

});
