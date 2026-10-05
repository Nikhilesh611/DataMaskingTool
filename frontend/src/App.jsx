import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import AuthView from './views/AuthView';
import DeveloperWorkspace from './views/DeveloperWorkspace';
import EnterpriseWorkspace from './views/EnterpriseWorkspace';
import { Shield, Sun, Moon, LogOut, ArrowRightLeft } from 'lucide-react';

function AppContent() {
  const { user, loading, logout } = useAuth();
  const [theme, setTheme] = useState(localStorage.getItem('dm_theme') || 'dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('dm_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        Loading platform workspace...
      </div>
    );
  }

  if (!user) {
    return <AuthView />;
  }

  const isEnterprise = user.account_type === 'enterprise';

  return (
    <div className="app-container">
      {/* Top Header */}
      <header className="top-nav">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            background: 'var(--accent)',
            color: '#fff',
          }}>
            <Shield size={18} />
          </div>
          <span style={{ fontWeight: 600, fontSize: '0.98rem' }}>
            Data Masking Platform
          </span>
          <span style={{
            fontSize: '0.75rem',
            padding: '0.2rem 0.6rem',
            borderRadius: '9999px',
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            color: 'var(--text-muted)',
            fontWeight: 500,
          }}>
            {user.tenant_name} ({user.tenant_slug})
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{
            fontSize: '0.75rem',
            padding: '0.25rem 0.65rem',
            borderRadius: '6px',
            background: user.account_type === 'enterprise' ? 'rgba(37, 99, 235, 0.12)' : 'rgba(16, 185, 129, 0.12)',
            border: user.account_type === 'enterprise' ? '1px solid rgba(37, 99, 235, 0.35)' : '1px solid rgba(16, 185, 129, 0.35)',
            color: user.account_type === 'enterprise' ? 'var(--accent)' : 'var(--success)',
            fontWeight: 600,
          }}>
            {user.account_type === 'enterprise' ? '🏢 Enterprise Workspace' : '🚀 Solo Developer Workspace'}
          </span>

          <a href="/docs" target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm">
            API Docs ↗
          </a>

          <button className="btn btn-secondary btn-sm" onClick={toggleTheme} title="Toggle Light/Dark Theme">
            {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>

          <button className="btn btn-secondary btn-sm" onClick={logout} title="Sign Out">
            <LogOut size={15} /> Logout
          </button>
        </div>
      </header>

      {/* Main Workspace Body */}
      {isEnterprise ? (
        <EnterpriseWorkspace />
      ) : (
        <DeveloperWorkspace />
      )}
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
