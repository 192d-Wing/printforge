import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { clearToken, decodeClaims, getToken } from '../lib/auth';

const NAV = [
  { path: '/', label: 'Dashboard' },
  { path: '/fleet', label: 'Fleet' },
  { path: '/jobs', label: 'Jobs' },
  { path: '/users', label: 'Users' },
  { path: '/alerts', label: 'Alerts' },
  { path: '/reports', label: 'Reports' },
];

export default function Layout() {
  const navigate = useNavigate();
  const token = getToken();
  const claims = token ? decodeClaims(token) : null;

  function logout() {
    clearToken();
    navigate('/login');
  }

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 bg-slate-900 text-slate-100 flex flex-col">
        <div className="p-4 border-b border-slate-700">
          <div className="font-bold">PrintForge</div>
          <div className="text-xs text-slate-400">Admin</div>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {NAV.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `block px-3 py-2 rounded ${
                  isActive
                    ? 'bg-slate-700 text-white'
                    : 'text-slate-300 hover:bg-slate-800'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-slate-700 text-xs">
          <div className="text-slate-400">Signed in</div>
          <div className="font-mono truncate">{claims?.sub ?? 'unknown'}</div>
          <button
            onClick={logout}
            className="mt-2 w-full text-center text-red-300 hover:text-red-200"
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
