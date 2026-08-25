import React from 'react';
import { SecureShieldProvider, useSecurity } from './SecureShieldProvider';

function SecurityDashboard() {
  const { isSecure, trustScore, report, refreshScan } = useSecurity();

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', background: '#0b0f19', color: '#fff', minHeight: '100vh' }}>
      <h1>Client Enterprise App</h1>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
        <div style={{ padding: '1rem', background: '#1e293b', borderRadius: '8px' }}>
          <h3>Security Verdict</h3>
          <p style={{ color: isSecure ? '#10b981' : '#ef4444', fontWeight: 'bold', fontSize: '1.2rem' }}>
            {report ? report.verdict : 'EVALUATING...'}
          </p>
        </div>
        <div style={{ padding: '1rem', background: '#1e293b', borderRadius: '8px' }}>
          <h3>Device Trust</h3>
          <p style={{ color: '#06b6d4', fontWeight: 'bold', fontSize: '1.2rem' }}>
            {trustScore}/100
          </p>
        </div>
      </div>
      <button 
        onClick={() => refreshScan()} 
        style={{ marginTop: '1.5rem', padding: '10px 20px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
      >
        Re-Scan & Ingest Telemetry
      </button>
    </div>
  );
}

export default function App() {
  return (
    <SecureShieldProvider>
      <SecurityDashboard />
    </SecureShieldProvider>
  );
}
