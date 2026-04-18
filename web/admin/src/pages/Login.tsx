import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { setToken } from '../lib/auth';

type LocationState = { from?: { pathname?: string } } | null;

export default function Login() {
  const [token, setLocalToken] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as LocationState)?.from?.pathname ?? '/';

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!token.trim()) return;
    setToken(token.trim());
    navigate(from, { replace: true });
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100">
      <form
        onSubmit={submit}
        className="bg-white rounded shadow p-6 w-full max-w-lg"
      >
        <h1 className="text-xl font-bold mb-1">PrintForge Admin — Sign in</h1>
        <p className="text-sm text-slate-600 mb-4">
          Dev mode: paste a PrintForge JWT below. A full OIDC flow replaces
          this when the <code>/api/v1/auth/session</code> exchange endpoint
          lands.
        </p>
        <textarea
          value={token}
          onChange={(e) => setLocalToken(e.target.value)}
          className="w-full h-32 p-2 border rounded font-mono text-xs"
          placeholder="eyJhbGciOiJFZERTQSIs..."
        />
        <button
          type="submit"
          className="mt-3 w-full bg-slate-900 text-white py-2 rounded hover:bg-slate-800"
        >
          Use this token
        </button>
      </form>
    </div>
  );
}
