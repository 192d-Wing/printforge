import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';

export default function Alerts() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ['alerts'],
    queryFn: api.alerts,
    refetchInterval: 15_000,
  });

  const ackMutation = useMutation({
    mutationFn: (id: string) => api.acknowledgeAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });

  if (isLoading) return <div>Loading alerts…</div>;
  if (error) return <div className="text-red-600">Failed to load alerts.</div>;
  if (!data) return null;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Alerts</h1>
      <div className="space-y-2">
        {data.alerts.length === 0 && (
          <div className="bg-white rounded shadow p-4 text-slate-600">
            No active alerts.
          </div>
        )}
        {data.alerts.map((a) => (
          <div
            key={a.alert_id}
            className="bg-white rounded shadow p-4 flex items-start justify-between"
          >
            <div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={a.severity} />
                <span className="text-xs text-slate-500">{a.category}</span>
                {a.printer_id && (
                  <span className="text-xs font-mono text-slate-500">
                    {a.printer_id}
                  </span>
                )}
              </div>
              <div className="font-semibold mt-1">{a.title}</div>
              <div className="text-sm text-slate-600">{a.description}</div>
              <div className="text-xs text-slate-500 mt-1">
                {a.site_id || '—'} · {new Date(a.created_at).toLocaleString()}
              </div>
            </div>
            <button
              onClick={() => ackMutation.mutate(a.alert_id)}
              disabled={ackMutation.isPending}
              className="text-xs px-3 py-1 rounded bg-slate-900 text-white hover:bg-slate-800 disabled:opacity-50"
            >
              Acknowledge
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color =
    severity === 'Critical'
      ? 'bg-red-100 text-red-800'
      : severity === 'Warning'
        ? 'bg-yellow-100 text-yellow-800'
        : 'bg-blue-100 text-blue-800';
  return <span className={`px-2 py-0.5 rounded text-xs ${color}`}>{severity}</span>;
}
