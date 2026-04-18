import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Role } from '../lib/types';

function roleLabel(role: Role): string {
  if (typeof role === 'string') return role;
  return `SiteAdmin:${role.SiteAdmin}`;
}

export default function Users() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['users'],
    queryFn: api.users,
  });

  if (isLoading) return <div>Loading users…</div>;
  if (error) return <div className="text-red-600">Failed to load users.</div>;
  if (!data) return null;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Users</h1>
      <div className="bg-white rounded shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="p-2">EDIPI</th>
              <th className="p-2">Name</th>
              <th className="p-2">Organization</th>
              <th className="p-2">Site</th>
              <th className="p-2">Roles</th>
              <th className="p-2">Status</th>
              <th className="p-2">Quota</th>
              <th className="p-2">Last login</th>
            </tr>
          </thead>
          <tbody>
            {data.users.map((u) => (
              <tr key={u.user_id} className="border-t">
                <td className="p-2 font-mono">
                  <Link
                    to={`/users/${encodeURIComponent(u.user_id)}`}
                    className="text-blue-700 hover:underline"
                  >
                    {u.user_id}
                  </Link>
                </td>
                <td className="p-2">{u.display_name}</td>
                <td className="p-2">{u.organization}</td>
                <td className="p-2">{u.site_id || '—'}</td>
                <td className="p-2 text-xs">
                  {u.roles.map(roleLabel).join(', ')}
                </td>
                <td className="p-2">
                  {u.active ? (
                    <span className="text-green-700">Active</span>
                  ) : (
                    <span className="text-slate-500">Suspended</span>
                  )}
                </td>
                <td className="p-2 text-xs">
                  {u.quota
                    ? `${u.quota.used}/${u.quota.limit} pages`
                    : '—'}
                </td>
                <td className="p-2 text-xs">
                  {u.last_login
                    ? new Date(u.last_login).toLocaleDateString()
                    : 'never'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="p-2 text-xs text-slate-500 border-t">
          {data.total_count} users total
        </div>
      </div>
    </div>
  );
}
