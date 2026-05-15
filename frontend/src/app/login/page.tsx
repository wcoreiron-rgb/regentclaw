'use client';
import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { Shield } from 'lucide-react';

const BASE = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : '/api/v1';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const body = new URLSearchParams();
      body.append('username', username);
      body.append('password', password);

      const res = await fetch(`${BASE}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });

      if (!res.ok) {
        const text = await res.text();
        let detail = 'Invalid username or password.';
        try {
          const json = JSON.parse(text);
          if (json.detail) detail = json.detail;
        } catch { /* use default */ }
        setError(detail);
        return;
      }

      const data = await res.json();
      localStorage.setItem('rc_token', data.access_token);
      router.replace('/dashboard');
    } catch (err: any) {
      setError(err?.message ?? 'Unable to reach the server. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--rc-bg-base, #0b0f1a)',
        padding: '1rem',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '400px',
          backgroundColor: 'var(--rc-bg-surface, #111827)',
          border: '1px solid var(--rc-border, #1f2937)',
          borderRadius: '1rem',
          padding: '2.5rem 2rem',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}
      >
        {/* Branding */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '3rem',
              height: '3rem',
              borderRadius: '0.75rem',
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              marginBottom: '0.75rem',
            }}
          >
            <Shield style={{ width: '1.5rem', height: '1.5rem', color: '#06b6d4' }} />
          </div>
          <h1
            style={{
              margin: 0,
              fontSize: '1.5rem',
              fontWeight: 700,
              color: 'var(--rc-text-1, #f9fafb)',
              letterSpacing: '-0.02em',
            }}
          >
            RegentClaw
          </h1>
          <p
            style={{
              margin: '0.25rem 0 0',
              fontSize: '0.875rem',
              color: 'var(--rc-text-2, #9ca3af)',
            }}
          >
            Zero Trust Security Ecosystem
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            <label
              htmlFor="username"
              style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--rc-text-2, #9ca3af)' }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              style={{
                padding: '0.625rem 0.875rem',
                borderRadius: '0.5rem',
                border: '1px solid var(--rc-border, #1f2937)',
                backgroundColor: 'var(--rc-bg-base, #0b0f1a)',
                color: 'var(--rc-text-1, #f9fafb)',
                fontSize: '0.9375rem',
                outline: 'none',
                width: '100%',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            <label
              htmlFor="password"
              style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--rc-text-2, #9ca3af)' }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              style={{
                padding: '0.625rem 0.875rem',
                borderRadius: '0.5rem',
                border: '1px solid var(--rc-border, #1f2937)',
                backgroundColor: 'var(--rc-bg-base, #0b0f1a)',
                color: 'var(--rc-text-1, #f9fafb)',
                fontSize: '0.9375rem',
                outline: 'none',
                width: '100%',
                boxSizing: 'border-box',
              }}
            />
          </div>

          {error && (
            <div
              role="alert"
              style={{
                padding: '0.625rem 0.875rem',
                borderRadius: '0.5rem',
                backgroundColor: 'rgba(239,68,68,0.1)',
                border: '1px solid rgba(239,68,68,0.3)',
                color: '#fca5a5',
                fontSize: '0.8125rem',
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: '0.5rem',
              padding: '0.75rem',
              borderRadius: '0.5rem',
              border: 'none',
              backgroundColor: loading ? 'rgba(6,182,212,0.5)' : '#06b6d4',
              color: '#fff',
              fontWeight: 600,
              fontSize: '0.9375rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.15s',
            }}
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
