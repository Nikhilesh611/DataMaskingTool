import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, KeyRound, Building2, User, ArrowRight, CheckCircle2 } from 'lucide-react';

export default function AuthView() {
  const { login, signup } = useAuth();
  const [isLogin, setIsLogin] = useState(true);
  const [accountType, setAccountType] = useState('developer'); // 'developer' | 'enterprise'

  // Form states
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        await login(email, password);
      } else {
        await signup({
          email,
          password,
          full_name: fullName,
          account_type: accountType,
          organization_name: orgName || (accountType === 'enterprise' ? 'Acme Corp' : 'Personal Workspace'),
        });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Quick 1-click test credentials for capstone demo
  const handleQuickDemo = async (type) => {
    setError('');
    setLoading(true);
    try {
      const demoEmail = type === 'enterprise' ? 'admin@acme-corp.test' : 'dev@antigravity.test';
      const demoPassword = type === 'enterprise' ? 'enterprise_secret_pw' : 'developer_secret_pw';
      try {
        await login(demoEmail, demoPassword);
      } catch (err) {
        // If account doesn't exist, create it on the fly
        await signup({
          email: demoEmail,
          password: demoPassword,
          full_name: type === 'enterprise' ? 'Acme CISO' : 'Lead Developer',
          account_type: type,
          organization_name: type === 'enterprise' ? 'Acme Financial Services' : 'Solo Dev Project',
        });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem',
      background: 'radial-gradient(circle at 50% 20%, var(--bg-panel) 0%, var(--bg-base) 100%)',
    }}>
      <div style={{ width: '100%', maxWidth: '440px' }}>
        {/* Header Branding */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            background: 'var(--accent)',
            color: '#fff',
            marginBottom: '1rem',
            boxShadow: '0 0 24px rgba(37, 99, 235, 0.4)',
          }}>
            <Shield size={26} />
          </div>
          <h1 style={{ fontSize: '1.45rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
            Enterprise Data Masking
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.35rem' }}>
            Zero-disk streaming data masking control plane
          </p>
        </div>

        {/* Card */}
        <div className="card" style={{ padding: '2rem' }}>
          {/* Persona Selector (when signing up) */}
          {!isLogin && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <button
                type="button"
                className={`btn ${accountType === 'developer' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.82rem', padding: '0.65rem 0.5rem' }}
                onClick={() => setAccountType('developer')}
              >
                <User size={15} /> Solo Developer
              </button>
              <button
                type="button"
                className={`btn ${accountType === 'enterprise' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.82rem', padding: '0.65rem 0.5rem' }}
                onClick={() => setAccountType('enterprise')}
              >
                <Building2 size={15} /> Enterprise Admin
              </button>
            </div>
          )}

          {error && (
            <div className="alert-box alert-error" style={{ display: 'block', marginBottom: '1.25rem' }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {!isLogin && (
              <>
                <div className="form-group">
                  <label>Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="e.g. Aditya Nangarath"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>{accountType === 'enterprise' ? 'Company Name' : 'Project / Workspace Name'}</label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    placeholder={accountType === 'enterprise' ? 'e.g. Acme Financial' : 'e.g. My Next.js App'}
                    required
                  />
                </div>
              </>
            )}

            <div className="form-group">
              <label>Work Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                required
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
              style={{ marginTop: '0.5rem', width: '100%', padding: '0.75rem' }}
            >
              {loading ? 'Please wait...' : isLogin ? 'Sign In to Workspace' : 'Create Free Workspace'}
              <ArrowRight size={16} />
            </button>
          </form>

          {/* Toggle between Login and Signup */}
          <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.84rem', color: 'var(--text-muted)' }}>
            {isLogin ? (
              <span>
                New to the platform?{' '}
                <button
                  type="button"
                  onClick={() => { setIsLogin(false); setError(''); }}
                  style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontWeight: 600 }}
                >
                  Create an account
                </button>
              </span>
            ) : (
              <span>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => { setIsLogin(true); setError(''); }}
                  style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontWeight: 600 }}
                >
                  Sign in
                </button>
              </span>
            )}
          </div>

          {/* 1-Click Demo Launcher */}
          <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textAlign: 'center', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
              Instant Demo Access (Professor & Evaluators)
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => handleQuickDemo('developer')}
                disabled={loading}
              >
                Solo Developer 🚀
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => handleQuickDemo('enterprise')}
                disabled={loading}
              >
                Enterprise Admin 🏢
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
