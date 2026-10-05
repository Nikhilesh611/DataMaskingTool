import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { Terminal, Shield, Key, Play, Copy, Check, Plus, Trash2, RefreshCw } from 'lucide-react';

export default function DeveloperWorkspace() {
  const { user, activeKey } = useAuth();
  const [activeTab, setActiveTab] = useState('quickstart'); // 'quickstart' | 'policy' | 'keys' | 'console'

  // Data states
  const [keys, setKeys] = useState([]);
  const [primaryKey, setPrimaryKey] = useState(activeKey || '');
  const [policyYaml, setPolicyYaml] = useState('');
  const [policyName, setPolicyName] = useState('analyst');
  const [policyStatus, setPolicyStatus] = useState('');

  // Console states
  const [consoleFormat, setConsoleFormat] = useState('json');
  const [consoleInput, setConsoleInput] = useState(JSON.stringify({
    client_name: "Robert Smith",
    ssn: "123-45-6789",
    salary: 95000,
    credit_card: "4111-2222-3333-4444",
    email: "robert.smith@example.com"
  }, null, 2));
  const [consoleOutput, setConsoleOutput] = useState('// Output will appear here...');
  const [consoleLatency, setConsoleLatency] = useState(null);
  const [consoleLoading, setConsoleLoading] = useState(false);

  // New API Key form
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newGeneratedKey, setNewGeneratedKey] = useState(null);

  // Load API Keys and Policy
  const loadData = async () => {
    if (!user?.tenant_id) return;
    try {
      // 1. Fetch API Keys
      const keysRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys`);
      if (keysRes.ok) {
        const keysData = await keysRes.json();
        const keyList = Array.isArray(keysData) ? keysData : [];
        setKeys(keyList);
        if (!primaryKey && keyList.length > 0) {
          setPrimaryKey(keyList[0].key_prefix + '...');
        }
      }

      // 2. Fetch Policies
      const polRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/policies`);
      if (polRes.ok) {
        const polData = await polRes.json();
        if (Array.isArray(polData) && polData.length > 0) {
          setPolicyYaml(polData[0].policy_yaml);
          setPolicyName(polData[0].name);
        }
      }
    } catch (err) {
      console.error("Failed to load developer data:", err);
    }
  };

  useEffect(() => {
    loadData();
  }, [user?.tenant_id]);

  const handleSavePolicy = async (e) => {
    e.preventDefault();
    setPolicyStatus('Saving...');
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: policyName,
          policy_yaml: policyYaml,
          is_active: true
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Validation failed');
      }
      setPolicyStatus('Policy compiled & saved successfully!');
      setTimeout(() => setPolicyStatus(''), 4000);
    } catch (err) {
      setPolicyStatus('Error: ' + err.message);
    }
  };

  const handleCreateKey = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName || 'Development Key', role: 'analyst' }),
      });
      if (res.ok) {
        const created = await res.json();
        setNewGeneratedKey(created.api_key);
        setPrimaryKey(created.api_key);
        setNewKeyName('');
        await loadData();
      }
    } catch (err) {
      alert('Failed to generate key: ' + err.message);
    }
  };

  const handleRevokeKey = async (keyId) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return;
    try {
      await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys/${keyId}`, { method: 'DELETE' });
      await loadData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const handleExecuteConsole = async () => {
    setConsoleLoading(true);
    setConsoleOutput('// Masking data stream...');
    const t0 = performance.now();

    try {
      let parsed = consoleInput;
      if (consoleFormat === 'json') {
        try { parsed = JSON.parse(consoleInput); } catch (e) { /* raw text */ }
      }

      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: consoleFormat, data: parsed, role: policyName }),
      });

      const t1 = performance.now();
      setConsoleLatency((t1 - t0).toFixed(2));

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Masking request failed');
      }

      const data = await res.json();
      if (typeof data.masked_output === 'object') {
        setConsoleOutput(JSON.stringify(data.masked_output, null, 2));
      } else {
        setConsoleOutput(data.masked_output);
      }
    } catch (err) {
      setConsoleOutput('// Error:\n' + err.message);
    } finally {
      setConsoleLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  const activeKeyStr = primaryKey || (keys[0] ? keys[0].key_prefix + '...' : 'dm_live_your_secret_key');

  return (
    <div className="main-body">
      {/* Sidebar */}
      <aside className="sidebar">
        <div style={{ padding: '0.5rem 0.75rem', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Solo Developer
        </div>
        <button
          className={`nav-btn ${activeTab === 'quickstart' ? 'active' : ''}`}
          onClick={() => setActiveTab('quickstart')}
        >
          <Terminal size={17} /> Overview & API
        </button>
        <button
          className={`nav-btn ${activeTab === 'policy' ? 'active' : ''}`}
          onClick={() => setActiveTab('policy')}
        >
          <Shield size={17} /> My Masking Policy
        </button>
        <button
          className={`nav-btn ${activeTab === 'keys' ? 'active' : ''}`}
          onClick={() => setActiveTab('keys')}
        >
          <Key size={17} /> API Keys ({keys.length})
        </button>
        <button
          className={`nav-btn ${activeTab === 'console' ? 'active' : ''}`}
          onClick={() => setActiveTab('console')}
        >
          <Play size={17} /> Live API Console
        </button>
      </aside>

      {/* Main Content Area */}
      <main className="content-area">
        {/* TAB 1: OVERVIEW & QUICKSTART */}
        {activeTab === 'quickstart' && (
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Developer Quickstart</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem', marginBottom: '1.5rem' }}>
              Zero-disk streaming data masking service. Send sensitive payloads to <code>/v1/mask</code> and receive masked data in sub-millisecond execution.
            </p>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Active API Key</div>
                <button className="btn btn-secondary btn-sm" onClick={() => setActiveTab('keys')}>Manage Keys</button>
              </div>
              <div className="card-body">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', background: 'var(--bg-panel)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
                  <code style={{ fontSize: '0.9rem', color: 'var(--code-text)', flex: 1 }}>{activeKeyStr}</code>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(activeKeyStr)}>
                    <Copy size={14} /> Copy
                  </button>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>cURL (Terminal)</div>
                <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(`curl -X POST http://127.0.0.1:8000/v1/mask \\\n  -H "X-API-Key: ${activeKeyStr}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"client_name":"Robert Smith","ssn":"123-45-6789","salary":95000,"credit_card":"4111-2222-3333-4444"}'`)}>
                  <Copy size={14} /> Copy Command
                </button>
              </div>
              <div className="card-body" style={{ padding: 0 }}>
                <pre className="code-snippet" style={{ margin: 0, borderRadius: '0 0 8px 8px' }}>
{`curl -X POST http://127.0.0.1:8000/v1/mask \\
  -H "X-API-Key: ${activeKeyStr}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_name": "Robert Smith",
    "ssn": "123-45-6789",
    "salary": 95000,
    "credit_card": "4111-2222-3333-4444"
  }'`}
                </pre>
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Python (requests / httpx)</div>
                <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(`import requests\n\nres = requests.post(\n    "http://127.0.0.1:8000/v1/mask",\n    headers={"X-API-Key": "${activeKeyStr}"},\n    json={\n        "client_name": "Robert Smith",\n        "ssn": "123-45-6789",\n        "salary": 95000,\n        "credit_card": "4111-2222-3333-4444"\n    }\n)\nprint("Masked Result:", res.json())`)}>
                  <Copy size={14} /> Copy Code
                </button>
              </div>
              <div className="card-body" style={{ padding: 0 }}>
                <pre className="code-snippet" style={{ margin: 0, borderRadius: '0 0 8px 8px' }}>
{`import requests

response = requests.post(
    "http://127.0.0.1:8000/v1/mask",
    headers={"X-API-Key": "${activeKeyStr}"},
    json={
        "client_name": "Robert Smith",
        "ssn": "123-45-6789",
        "salary": 95000,
        "credit_card": "4111-2222-3333-4444"
    }
)
print("Masked Result:", response.json())`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: MY MASKING POLICY */}
        {activeTab === 'policy' && (
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Custom Masking Policy</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem', marginBottom: '1.5rem' }}>
              Configure field-level masking rules (suppress, redact, mask_pattern, pseudonymize) enforced on incoming data for your project.
            </p>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Policy YAML Specification</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                  Validated against Pydantic schema v3.0
                </div>
              </div>
              <div className="card-body">
                <form onSubmit={handleSavePolicy}>
                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label>Policy Name / Assigned Role</label>
                    <input
                      type="text"
                      value={policyName}
                      onChange={(e) => setPolicyName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>YAML Configuration</label>
                    <textarea
                      rows={14}
                      value={policyYaml}
                      onChange={(e) => setPolicyYaml(e.target.value)}
                      spellCheck={false}
                      required
                    />
                  </div>

                  <div style={{ marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <button type="submit" className="btn btn-primary">
                      Save & Deploy Policy
                    </button>
                    {policyStatus && (
                      <span style={{ fontSize: '0.85rem', color: policyStatus.startsWith('Error') ? 'var(--danger)' : 'var(--success)' }}>
                        {policyStatus}
                      </span>
                    )}
                  </div>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: API KEYS */}
        {activeTab === 'keys' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>API Keys</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
                  Secret keys used by your applications, backend workers, and microservices to call the masking API.
                </p>
              </div>
              <button className="btn btn-primary" onClick={() => setShowKeyModal(!showKeyModal)}>
                <Plus size={15} /> Create API Key
              </button>
            </div>

            {/* Generated Key Alert */}
            {newGeneratedKey && (
              <div className="alert-box alert-success" style={{ display: 'block', marginBottom: '1.5rem' }}>
                <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>🎉 New API Key Generated</div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <code style={{ fontSize: '0.95rem', color: 'var(--text-main)', background: 'var(--bg-base)', padding: '0.4rem 0.6rem' }}>
                    {newGeneratedKey}
                  </code>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(newGeneratedKey)}>
                    <Copy size={13} /> Copy
                  </button>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
                  Make sure to copy this key now. It will not be shown again.
                </div>
              </div>
            )}

            {/* Create Key Form */}
            {showKeyModal && (
              <div className="card" style={{ marginBottom: '1.5rem' }}>
                <div className="card-header">
                  <div style={{ fontWeight: 600 }}>Generate Secret API Key</div>
                </div>
                <div className="card-body">
                  <form onSubmit={handleCreateKey} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
                    <div className="form-group" style={{ flex: 1 }}>
                      <label>Key Name / Service Label</label>
                      <input
                        type="text"
                        value={newKeyName}
                        onChange={(e) => setNewKeyName(e.target.value)}
                        placeholder="e.g. Production Billing Microservice"
                        required
                      />
                    </div>
                    <button type="submit" className="btn btn-primary">Generate</button>
                    <button type="button" className="btn btn-secondary" onClick={() => setShowKeyModal(false)}>Cancel</button>
                  </form>
                </div>
              </div>
            )}

            {/* Table */}
            <div className="card">
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Key Name</th>
                      <th>Key Prefix</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {keys.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                          No API keys generated yet. Click "+ Create API Key" above.
                        </td>
                      </tr>
                    ) : (
                      keys.map((k) => (
                        <tr key={k.id}>
                          <td><strong>{k.name}</strong></td>
                          <td><code>{k.key_prefix}...</code></td>
                          <td><span className="badge badge-active">{k.role}</span></td>
                          <td><span className="badge badge-active"><span className="badge-dot"></span>Active</span></td>
                          <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>{new Date(k.created_at).toLocaleDateString()}</td>
                          <td>
                            <button className="btn btn-danger btn-sm" onClick={() => handleRevokeKey(k.id)}>
                              <Trash2 size={13} /> Revoke
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: LIVE API CONSOLE */}
        {activeTab === 'console' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div>
                <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Live API Console</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
                  Interactive testbench. Test your payload against your saved masking policy in real-time.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <select
                  value={consoleFormat}
                  onChange={(e) => setConsoleFormat(e.target.value)}
                  style={{ width: '100px' }}
                >
                  <option value="json">JSON</option>
                  <option value="xml">XML</option>
                  <option value="yaml">YAML</option>
                </select>

                <button
                  className="btn btn-primary"
                  onClick={handleExecuteConsole}
                  disabled={consoleLoading}
                >
                  <Play size={15} /> {consoleLoading ? 'Masking...' : 'Send API Request'}
                </button>
              </div>
            </div>

            {/* Split Screen Console */}
            <div className="console-split">
              <div className="console-pane">
                <div className="console-bar">
                  <span>Inbound Payload</span>
                  <span style={{ color: 'var(--text-dim)' }}>{consoleFormat.toUpperCase()}</span>
                </div>
                <textarea
                  className="console-input"
                  value={consoleInput}
                  onChange={(e) => setConsoleInput(e.target.value)}
                  spellCheck={false}
                />
              </div>

              <div className="console-pane">
                <div className="console-bar">
                  <span>Outbound Masked Result</span>
                  <span style={{ color: 'var(--success)' }}>
                    {consoleLatency ? `200 OK (${consoleLatency}ms)` : 'Ready'}
                  </span>
                </div>
                <div className="console-output">{consoleOutput}</div>
              </div>
            </div>

            <div style={{ marginTop: '1rem', display: 'flex', gap: '2rem', fontSize: '0.82rem', color: 'var(--text-dim)' }}>
              <div>Latency: <strong style={{ color: 'var(--text-main)' }}>{consoleLatency ? `${consoleLatency} ms` : '—'}</strong></div>
              <div>Disk Writes: <strong style={{ color: 'var(--success)' }}>0 Bytes (Pure In-Memory)</strong></div>
              <div>Isolation: <strong style={{ color: 'var(--accent)' }}>PostgreSQL Tenant Scoped</strong></div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
