import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api';

export default function UserDetail() {
  const { edipi } = useParams<{ edipi: string }>();
  const quota = useQuery({
    queryKey: ['quota', edipi],
    queryFn: () => api.userQuota(edipi!),
    enabled: !!edipi,
  });

  if (!edipi) return <div>Missing user id.</div>;

  return (
    <div>
      <Link to="/users" className="text-blue-700 hover:underline text-sm">
        ← back to users
      </Link>
      <h1 className="text-2xl font-bold mt-2 mb-4">
        User <span className="font-mono">{edipi}</span>
      </h1>
      <section className="bg-white rounded shadow p-4">
        <h2 className="font-semibold mb-3">Quota detail</h2>
        {quota.isLoading && <div>Loading quota…</div>}
        {quota.error && (
          <div className="text-slate-600">
            No quota counter for this user.
          </div>
        )}
        {quota.data && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <Stat label="Pages used" value={quota.data.pages_used} />
            <Stat label="Pages remaining" value={quota.data.pages_remaining} />
            <Stat label="Page limit" value={quota.data.page_limit} />
            <Stat label="Color used" value={quota.data.color_pages_used} />
            <Stat
              label="Color remaining"
              value={quota.data.color_pages_remaining}
            />
            <Stat label="Color limit" value={quota.data.color_page_limit} />
            <Stat label="Burst used" value={quota.data.burst_pages_used} />
            <Stat label="Burst limit" value={quota.data.burst_limit} />
          </div>
        )}
        {quota.data && (
          <div className="text-xs text-slate-500 mt-4">
            Billing period {new Date(quota.data.period_start).toLocaleDateString()}
            {' – '}
            {new Date(quota.data.period_end).toLocaleDateString()}
          </div>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="p-3 bg-slate-50 rounded">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-lg font-bold">{value.toLocaleString()}</div>
    </div>
  );
}
