import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

function Kpi({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-white rounded shadow p-4">
      <div className="text-xs text-slate-500 uppercase">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
  );
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: api.dashboard,
    // Dashboard is polled so the active-alert / held-jobs counters stay
    // roughly fresh without a manual refresh.
    refetchInterval: 30_000,
  });

  if (isLoading) return <div>Loading…</div>;
  if (error) return <div className="text-red-600">Failed to load KPIs.</div>;
  if (!data) return null;

  const cost = (data.monthly_cost_cents / 100).toFixed(2);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Kpi label="Total printers" value={data.total_printers} />
        <Kpi label="Online" value={data.online_printers} />
        <Kpi label="Errors" value={data.error_printers} />
        <Kpi label="In maintenance" value={data.maintenance_printers} />
        <Kpi label="Held jobs" value={data.held_jobs} />
        <Kpi label="Active jobs" value={data.active_jobs} />
        <Kpi label="Monthly pages" value={data.monthly_pages.toLocaleString()} />
        <Kpi label="Monthly cost" value={`$${cost}`} />
        <Kpi label="Active alerts" value={data.active_alerts} />
      </div>
      <div className="text-xs text-slate-500 mt-4">
        Computed at {new Date(data.computed_at).toLocaleString()}
      </div>
    </div>
  );
}
