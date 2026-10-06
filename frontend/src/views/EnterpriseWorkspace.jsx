import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { Building2, Layers, ShieldCheck, FileText, Plus, Trash2, Edit3, RefreshCw, Key, Copy } from 'lucide-react';

export default function EnterpriseWorkspace() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('policies'); // default to 'policies' as requested

  // IdP state
  const [idpIssuer, setIdpIssuer] = useState('http://localhost:8081');
  const [idpJwks, setIdpJwks] = useState('http://localhost:8081/jwks.json');
  const [idpAudience, setIdpAudience] = useState('masking-api');
  const [idpGroupsClaim, setIdpGroupsClaim] = useState('groups');
  const [idpTestStatus, setIdpTestStatus] = useState(null);

  // Mappings state
  const [mappings, setMappings] = useState([]);
  const [newGroup, setNewGroup] = useState('');
  const [newPolicyId, setNewPolicyId] = useState('');
  const [newInternalRole, setNewInternalRole] = useState('');
  const [newPriority, setNewPriority] = useState(10);

  // Policies state
  const [policies, setPolicies] = useState([]);
  const [editingPolicyName, setEditingPolicyName] = useState('');
  const [editingPolicyYaml, setEditingPolicyYaml] = useState('');
  const [policySaveStatus, setPolicySaveStatus] = useState('');

  // Audit state
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // API Keys (Service Accounts) state
  const [keys, setKeys] = useState([]);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyRole, setNewKeyRole] = useState('');
  const [newGeneratedKey, setNewGeneratedKey] = useState(null);

  const loadEnterpriseData = async () => {
    if (!user?.tenant_id) return;
    try {
      // 1. Load IdP configs
      const idpRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/idp`);
      if (idpRes.ok) {
        const idpData = await idpRes.json();
        if (Array.isArray(idpData) && idpData.length > 0) {
          setIdpIssuer(idpData[0].issuer_url || '');
          setIdpJwks(idpData[0].jwks_uri || '');
          setIdpAudience(idpData[0].audience || '');
          setIdpGroupsClaim(idpData[0].groups_claim || 'groups');
        }
      }

      // 2. Load Policies
      const polRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/policies`);
      if (polRes.ok) {
        const polData = await polRes.json();
        const pList = Array.isArray(polData) ? polData : [];
        setPolicies(pList);
        if (pList.length > 0) {
          if (!newPolicyId) {
            setNewPolicyId(pList[0].id);
          }
          setEditingPolicyName((prev) => prev || pList[0].name);
          setEditingPolicyYaml((prev) => prev || pList[0].policy_yaml);
        }
      }

      // 3. Load Group Mappings
      const mapRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/mappings`);
      if (mapRes.ok) {
        const mapData = await mapRes.json();
        setMappings(Array.isArray(mapData) ? mapData : []);
      }

      // 4. Load Service Account API Keys
      const keysRes = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys`);
      if (keysRes.ok) {
        const keysData = await keysRes.json();
        setKeys(Array.isArray(keysData) ? keysData : []);
      }
    } catch (err) {
      console.error("Failed to load enterprise data:", err);
    }
  };

  const loadAuditLogs = async () => {
    if (!user?.tenant_id) return;
    setAuditLoading(true);
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/audit-logs`);
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    } finally {
      setAuditLoading(false);
    }
  };

  useEffect(() => {
    loadEnterpriseData();
  }, [user?.tenant_id]);

  useEffect(() => {
    if (activeTab === 'audit') {
      loadAuditLogs();
    }
  }, [activeTab]);

  const handleTestIdP = async () => {
    setIdpTestStatus({ loading: true, message: 'Probing JWKS public key endpoint...' });
    try {
      const res = await fetch('/api/v1/admin/idp/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issuer_url: idpIssuer, jwks_uri: idpJwks || null }),
      });
      const data = await res.json();
      setIdpTestStatus({ loading: false, success: data.success, message: data.message });
    } catch (err) {
      setIdpTestStatus({ loading: false, success: false, message: 'Failed: ' + err.message });
    }
  };

  const handleSaveIdP = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/idp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider_type: 'oidc',
          issuer_url: idpIssuer,
          jwks_uri: idpJwks || null,
          audience: idpAudience || null,
          groups_claim: idpGroupsClaim,
          is_active: true
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to save IdP');
      }
      alert('Enterprise IdP configuration saved successfully!');
      await loadEnterpriseData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const handleSavePolicy = async (e) => {
    e.preventDefault();
    setPolicySaveStatus('Saving policy...');
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: editingPolicyName,
          policy_yaml: editingPolicyYaml,
          is_active: true,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Validation error');
      }
      setPolicySaveStatus(`Policy "${editingPolicyName}" compiled and saved into database!`);
      await loadEnterpriseData();
      setTimeout(() => setPolicySaveStatus(''), 4000);
    } catch (err) {
      setPolicySaveStatus('Error: ' + err.message);
    }
  };

  const loadTemplate = (type) => {
    if (type === 'enterprise') {
      setEditingPolicyName('Enterprise-Unified-Policy');
      setEditingPolicyYaml(`# Enterprise Unified Multi-Role Policy

roles:
  clinical-analyst:
    default_fallback: drop_subtree
  compliance-auditor:
    default_fallback: masked
  emergency-operator:
    default_fallback: default_allow

scopes:
  - path: "$.patients[*].personal_info"
    roles:
      clinical-analyst:
        strategy: masked
      compliance-auditor:
        strategy: masked
      emergency-operator:
        strategy: default_allow

  - path: "$.patients[*].billing"
    roles:
      clinical-analyst:
        strategy: drop_subtree
      compliance-auditor:
        strategy: masked
      emergency-operator:
        strategy: default_allow

rules:
  - selector: "$..ssn"
    technique: "suppress"
  - selector: "$..credit_card"
    technique: "mask_pattern"
    pattern: "****-****-****-{last4}"
`);
    } else if (type === 'blank') {
      setEditingPolicyName('');
      setEditingPolicyYaml('');
    }
  };

  const handleEditPolicyRow = (p) => {
    setEditingPolicyName(p.name);
    setEditingPolicyYaml(p.policy_yaml);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleDeletePolicy = async (policyId, policyName) => {
    if (!confirm(`Delete policy "${policyName}"? This may affect directory group mappings relying on it.`)) return;
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/policies/${policyId}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Failed to delete policy');
      await loadEnterpriseData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const handleAddMapping = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/mappings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          external_group: newGroup,
          policy_id: newPolicyId || (policies[0]?.id || ''),
          internal_role: newInternalRole || null,
          priority: parseInt(newPriority, 10),
          is_active: true,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed');
      }
      setNewGroup('');
      setNewInternalRole('');
      await loadEnterpriseData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const handleDeleteMapping = async (id) => {
    if (!confirm('Remove this directory group mapping?')) return;
    try {
      await fetch(`/api/v1/admin/tenants/${user.tenant_id}/mappings/${id}`, { method: 'DELETE' });
      await loadEnterpriseData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const handleCreateKey = async (e) => {
    e.preventDefault();
    try {
      const selectedRole = newKeyRole || (policies[0] ? policies[0].name : 'analyst');
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newKeyName || 'Backend Microservice Key',
          role: selectedRole,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to create key');
      }
      const data = await res.json();
      setNewGeneratedKey(data.api_key);
      setNewKeyName('');
      await loadEnterpriseData();
    } catch (err) {
      alert('Error creating API Key: ' + err.message);
    }
  };

  const handleRevokeKey = async (keyId, keyName) => {
    if (!confirm(`Revoke API key "${keyName}"? Any backend microservices using this key will immediately fail.`)) return;
    try {
      const res = await fetch(`/api/v1/admin/tenants/${user.tenant_id}/api-keys/${keyId}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Failed to revoke key');
      await loadEnterpriseData();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  return (
    <div className="main-body">
      {/* Sidebar */}
      <aside className="sidebar">
        <div style={{ padding: '0.5rem 0.75rem', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Enterprise Admin
        </div>
        <button
          className={`nav-btn ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          <ShieldCheck size={17} /> Masking Policies ({policies.length})
        </button>
        <button
          className={`nav-btn ${activeTab === 'rbac' ? 'active' : ''}`}
          onClick={() => setActiveTab('rbac')}
        >
          <Layers size={17} /> Group Mappings (RBAC)
        </button>
        <button
          className={`nav-btn ${activeTab === 'idp' ? 'active' : ''}`}
          onClick={() => setActiveTab('idp')}
        >
          <Building2 size={17} /> Identity Provider (SSO)
        </button>
        <button
          className={`nav-btn ${activeTab === 'keys' ? 'active' : ''}`}
          onClick={() => setActiveTab('keys')}
        >
          <Key size={17} /> Service Keys / API Keys ({keys.length})
        </button>
        <button
          className={`nav-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          <FileText size={17} /> Compliance Audit Ledger
        </button>
      </aside>

      {/* Main Content Area */}
      <main className="content-area">
        {/* TAB 1: MASKING POLICIES (Enterprise Custom Policy Configuration) */}
        {activeTab === 'policies' && (
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Corporate Masking Policies</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem', marginBottom: '1.5rem' }}>
              Configure departmental masking policies (Healthcare PHI, Financial PII, Auditor views) compiled into database.
            </p>

            {/* Policy Editor */}
            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Policy Editor</div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => loadTemplate('enterprise')}>
                    Enterprise Multi-Role Template
                  </button>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => loadTemplate('blank')}>
                    + New Empty Policy
                  </button>
                </div>
              </div>
              <div className="card-body">
                <form onSubmit={handleSavePolicy}>
                  <div className="form-group" style={{ marginBottom: '1rem', maxWidth: '320px' }}>
                    <label>Policy Name / Assigned Masking Role</label>
                    <input
                      type="text"
                      value={editingPolicyName}
                      onChange={(e) => setEditingPolicyName(e.target.value)}
                      placeholder="e.g. data-science or hipaa-analyst"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Policy Specification (YAML)</label>
                    <textarea
                      rows={14}
                      value={editingPolicyYaml}
                      onChange={(e) => setEditingPolicyYaml(e.target.value)}
                      spellCheck={false}
                      required
                    />
                  </div>
                  <div style={{ marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <button type="submit" className="btn btn-primary">
                      Save & Deploy Policy
                    </button>
                    {policySaveStatus && (
                      <span style={{ fontSize: '0.85rem', color: policySaveStatus.startsWith('Error') ? 'var(--danger)' : 'var(--success)' }}>
                        {policySaveStatus}
                      </span>
                    )}
                  </div>
                </form>
              </div>
            </div>

            {/* Policies Table */}
            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Active Policies for {user.tenant_name}</div>
              </div>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Policy / Role Name</th>
                      <th>Policy ID</th>
                      <th>Status</th>
                      <th>Last Updated</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                          No policies loaded. Click a template above to deploy one.
                        </td>
                      </tr>
                    ) : (
                      policies.map((p) => (
                        <tr key={p.id}>
                          <td><strong>{p.name}</strong></td>
                          <td><code style={{ fontSize: '0.75rem' }}>{p.id.substring(0, 8)}...</code></td>
                          <td><span className="badge badge-active"><span className="badge-dot"></span>Active</span></td>
                          <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>{new Date(p.updated_at).toLocaleDateString()}</td>
                          <td>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleEditPolicyRow(p)} style={{ marginRight: '0.4rem' }}>
                              <Edit3 size={13} /> Edit
                            </button>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleDeletePolicy(p.id, p.name)} style={{ color: 'var(--danger)' }}>
                              <Trash2 size={13} /> Delete
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

        {/* TAB 2: RBAC DIRECTORY MAPPINGS */}
        {activeTab === 'rbac' && (
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Directory Group-to-Policy Mappings (RBAC)</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem', marginBottom: '1.5rem' }}>
              Map corporate Active Directory / Okta groups to your masking policies with automatic priority conflict resolution.
            </p>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Add Group Binding</div>
              </div>
              <div className="card-body">
                {(() => {
                  const currentPolicy = policies.find(p => p.id === (newPolicyId || policies[0]?.id));
                  const rolesList = currentPolicy?.available_roles || [];
                  return (
                    <form onSubmit={handleAddMapping} style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1.5fr 1fr auto', gap: '0.75rem', alignItems: 'flex-end' }}>
                      <div className="form-group">
                        <label>Directory Group Claim</label>
                        <input
                          type="text"
                          value={newGroup}
                          onChange={(e) => setNewGroup(e.target.value)}
                          placeholder="e.g. acme-data-analysts"
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Target Policy</label>
                        <select
                          value={newPolicyId || (policies[0]?.id || '')}
                          onChange={(e) => {
                            setNewPolicyId(e.target.value);
                            setNewInternalRole('');
                          }}
                          required
                        >
                          {policies.map((p) => (
                            <option key={p.id} value={p.id}>{p.name}</option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group">
                        <label>Role in Policy</label>
                        {rolesList.length > 0 ? (
                          <select value={newInternalRole} onChange={(e) => setNewInternalRole(e.target.value)}>
                            <option value="">Default (Primary Policy Role)</option>
                            {rolesList.map((r) => (
                              <option key={r} value={r}>{r}</option>
                            ))}
                          </select>
                        ) : (
                          <input
                            type="text"
                            disabled
                            value="Universal (No Roles)"
                            style={{ opacity: 0.65, fontSize: '0.8rem' }}
                          />
                        )}
                      </div>
                      <div className="form-group">
                        <label>Priority</label>
                        <input
                          type="number"
                          value={newPriority}
                          onChange={(e) => setNewPriority(e.target.value)}
                          min={1}
                          max={1000}
                          required
                        />
                      </div>
                      <button type="submit" className="btn btn-primary">
                        <Plus size={15} /> Add Binding
                      </button>
                    </form>
                  );
                })()}
              </div>
            </div>

            <div className="card">
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Priority</th>
                      <th>Directory Group</th>
                      <th>Target Masking Policy</th>
                      <th>Assigned Role</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mappings.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                          No directory group mappings configured yet.
                        </td>
                      </tr>
                    ) : (
                      mappings.map((m) => (
                        <tr key={m.id}>
                          <td><span className="badge badge-active">Priority {m.priority}</span></td>
                          <td><code>{m.external_group}</code></td>
                          <td><strong>{m.policy_name || m.policy_id}</strong></td>
                          <td>
                            {m.internal_role ? (
                              <span className="badge" style={{ backgroundColor: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                                {m.internal_role}
                              </span>
                            ) : (
                              <span className="badge" style={{ backgroundColor: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' }}>
                                Default Role
                              </span>
                            )}
                          </td>
                          <td><span className="badge badge-active"><span className="badge-dot"></span>Active</span></td>
                          <td>
                            <button className="btn btn-danger btn-sm" onClick={() => handleDeleteMapping(m.id)}>
                              <Trash2 size={13} /> Remove
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

        {/* TAB 3: IDENTITY PROVIDER (SSO) */}
        {activeTab === 'idp' && (
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Enterprise Identity Provider (OIDC / SSO)</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem', marginBottom: '1.5rem' }}>
              Federate authentication with Okta, Azure Active Directory, or Keycloak using cryptographic JWKS public keys.
            </p>

            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Configure SSO Federation</div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIdpIssuer('http://localhost:8081');
                      setIdpJwks('http://localhost:8081/jwks.json');
                      setIdpAudience('masking-api');
                      setIdpGroupsClaim('groups');
                    }}
                  >
                    Load Local Acme SSO
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIdpIssuer('https://accounts.google.com');
                      setIdpJwks('https://www.googleapis.com/oauth2/v3/certs');
                      setIdpAudience('masking-service');
                      setIdpGroupsClaim('groups');
                    }}
                  >
                    Load Google OIDC
                  </button>
                </div>
              </div>
              <div className="card-body">
                <form onSubmit={handleSaveIdP}>
                  <div className="form-grid">
                    <div className="form-group">
                      <label>OIDC Issuer URL</label>
                      <input
                        type="url"
                        value={idpIssuer}
                        onChange={(e) => setIdpIssuer(e.target.value)}
                        placeholder="https://acme.okta.com/oauth2/default"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label>Explicit JWKS URI (Optional)</label>
                      <input
                        type="url"
                        value={idpJwks}
                        onChange={(e) => setIdpJwks(e.target.value)}
                        placeholder="https://acme.okta.com/oauth2/default/v1/keys"
                      />
                    </div>
                    <div className="form-group">
                      <label>Audience (aud)</label>
                      <input
                        type="text"
                        value={idpAudience}
                        onChange={(e) => setIdpAudience(e.target.value)}
                        placeholder="masking-service"
                      />
                    </div>
                    <div className="form-group">
                      <label>Directory Groups Claim Key</label>
                      <input
                        type="text"
                        value={idpGroupsClaim}
                        onChange={(e) => setIdpGroupsClaim(e.target.value)}
                        placeholder="groups"
                        required
                      />
                    </div>
                  </div>

                  <div style={{ marginTop: '1.25rem', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <button type="button" className="btn btn-secondary" onClick={handleTestIdP}>
                      Test JWKS Connection
                    </button>
                    <button type="submit" className="btn btn-primary">
                      Save Provider Configuration
                    </button>
                  </div>
                </form>

                {idpTestStatus && (
                  <div
                    className={`alert-box ${idpTestStatus.success ? 'alert-success' : 'alert-error'}`}
                    style={{ display: 'block', marginTop: '1rem' }}
                  >
                    {idpTestStatus.message}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: SERVICE ACCOUNTS / API KEYS */}
        {activeTab === 'keys' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Service Accounts & API Keys</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
                  Generate long-lived secret keys for automated backend daemons, ETL pipelines, and microservices. Each key directly binds to an enterprise masking policy.
                </p>
              </div>
              <button className="btn btn-primary" onClick={() => setShowKeyModal(!showKeyModal)}>
                <Plus size={15} /> Create Service Key
              </button>
            </div>

            {/* Generated Key Alert */}
            {newGeneratedKey && (
              <div className="alert-box alert-success" style={{ display: 'block', marginBottom: '1.5rem' }}>
                <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>🎉 New Enterprise Service Key Generated</div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <code style={{ fontSize: '0.95rem', color: 'var(--text-main)', background: 'var(--bg-base)', padding: '0.4rem 0.6rem' }}>
                    {newGeneratedKey}
                  </code>
                  <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(newGeneratedKey)}>
                    <Copy size={13} /> Copy Key
                  </button>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
                  Make sure to copy this key now. For zero-trust security, the raw key is never stored in plain text and cannot be retrieved later.
                </div>
              </div>
            )}

            {/* Create Key Form */}
            {showKeyModal && (
              <div className="card" style={{ marginBottom: '1.5rem' }}>
                <div className="card-header">
                  <div style={{ fontWeight: 600 }}>Create Backend Service Key</div>
                </div>
                <div className="card-body">
                  <form onSubmit={handleCreateKey} style={{ display: 'grid', gridTemplateColumns: '2fr 2fr auto auto', gap: '0.75rem', alignItems: 'flex-end' }}>
                    <div className="form-group">
                      <label>Service Label / Purpose</label>
                      <input
                        type="text"
                        value={newKeyName}
                        onChange={(e) => setNewKeyName(e.target.value)}
                        placeholder="e.g. Nightly-ETL-Pipeline"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label>Bound Policy / Role</label>
                      <select value={newKeyRole} onChange={(e) => setNewKeyRole(e.target.value)}>
                        {policies.map((p) => (
                          <option key={p.id} value={p.name}>{p.name}</option>
                        ))}
                      </select>
                    </div>
                    <button type="submit" className="btn btn-primary">Generate</button>
                    <button type="button" className="btn btn-secondary" onClick={() => setShowKeyModal(false)}>Cancel</button>
                  </form>
                </div>
              </div>
            )}

            {/* Table */}
            <div className="card" style={{ marginBottom: '1.5rem' }}>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Service Name</th>
                      <th>Key Prefix</th>
                      <th>Bound Policy</th>
                      <th>Status</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {keys.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                          No service keys created yet. Click "+ Create Service Key" above.
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
                            <button className="btn btn-danger btn-sm" onClick={() => handleRevokeKey(k.id, k.name)}>
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

            {/* Quickstart Call Snippet */}
            <div className="card">
              <div className="card-header">
                <div style={{ fontWeight: 600 }}>Daemon / Microservice Call (cURL)</div>
              </div>
              <div className="card-body" style={{ padding: 0 }}>
                <pre className="code-snippet" style={{ margin: 0, borderRadius: '0 0 8px 8px' }}>
{`curl.exe -X POST http://127.0.0.1:8000/v1/mask \\
  -H "X-API-Key: ${keys[0] ? keys[0].key_prefix + '...' : 'dm_live_your_service_key'}" \\
  -H "Content-Type: application/json" \\
  -d '{"patient_id": "PT-98124", "ssn": "123-45-6789", "salary": 145000}'`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: COMPLIANCE AUDIT LEDGER */}
        {activeTab === 'audit' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Zero-PII Compliance Audit Ledger</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
                  Cryptographically verifiable compliance log of all data masking requests. Plain payload data is never stored.
                </p>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={loadAuditLogs} disabled={auditLoading}>
                <RefreshCw size={14} className={auditLoading ? 'spin' : ''} /> Refresh Ledger
              </button>
            </div>

            <div className="card">
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Caller / Key</th>
                      <th>Policy Applied</th>
                      <th>Format</th>
                      <th>Execution Time</th>
                      <th>Request ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                          No audit events recorded yet. Call <code>POST /v1/mask</code> to stream audit records.
                        </td>
                      </tr>
                    ) : (
                      auditLogs.map((l) => (
                        <tr key={l.id}>
                          <td style={{ color: 'var(--text-dim)', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                            {l.timestamp ? new Date(l.timestamp).toLocaleString(undefined, {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit'
                            }) : '—'}
                          </td>
                          <td><code>{l.user_id || 'anonymous'}</code></td>
                          <td><strong>{l.policy_name || 'default'}</strong></td>
                          <td><code>{l.format || 'json'}</code></td>
                          <td style={{ fontFamily: 'JetBrains Mono' }}>{l.execution_time_ms ? `${l.execution_time_ms}ms` : '< 1ms'}</td>
                          <td style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{l.request_id || '—'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
