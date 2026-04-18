import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export default function Fleet() {
  const overview = useQuery({
    queryKey: ['fleetOverview'],
    queryFn: api.fleetOverview,
    refetchInterval: 30_000,
  });
  const printers = useQuery({
    queryKey: ['fleetPrinters'],
    queryFn: api.fleetPrinters,
  });

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Fleet</h1>
      {overview.data && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          {(
            [
              ['Online', overview.data.online],
              ['Printing', overview.data.printing],
              ['Error', overview.data.error],
              ['Maintenance', overview.data.maintenance],
              ['Offline', overview.data.offline],
            ] as const
          ).map(([label, count]) => (
            <div key={label} className="bg-white rounded shadow p-3">
              <div className="text-xs text-slate-500">{label}</div>
              <div className="text-xl font-bold">{count}</div>
            </div>
          ))}
        </div>
      )}
      {printers.isLoading && <div>Loading printers…</div>}
      {printers.error && <div className="text-red-600">Failed to load printers.</div>}
      {printers.data && (
        <div className="bg-white rounded shadow overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-100 text-left">
              <tr>
                <th className="p-2">Printer</th>
                <th className="p-2">Model</th>
                <th className="p-2">Site</th>
                <th className="p-2">Status</th>
                <th className="p-2">Health</th>
                <th className="p-2">Paper</th>
                <th className="p-2">Toner</th>
              </tr>
            </thead>
            <tbody>
              {printers.data.printers.map((p) => {
                const toner = Math.min(
                  p.supply_levels.toner_k,
                  p.supply_levels.toner_c,
                  p.supply_levels.toner_m,
                  p.supply_levels.toner_y,
                );
                return (
                  <tr key={p.printer_id} className="border-t">
                    <td className="p-2 font-mono">{p.printer_id}</td>
                    <td className="p-2">
                      {p.model.vendor} {p.model.model}
                    </td>
                    <td className="p-2">{p.site_id || '—'}</td>
                    <td className="p-2">
                      <StatusBadge status={p.status} />
                    </td>
                    <td className="p-2">
                      {(p.health_score * 100).toFixed(0)}%
                    </td>
                    <td className="p-2">{p.supply_levels.paper}%</td>
                    <td className="p-2">{toner}%</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="p-2 text-xs text-slate-500 border-t">
            {printers.data.total_count} printers total
          </div>
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color =
    status === 'Online' || status === 'Printing'
      ? 'bg-green-100 text-green-800'
      : status === 'Error'
        ? 'bg-red-100 text-red-800'
        : 'bg-slate-100 text-slate-700';
  return <span className={`px-2 py-0.5 rounded text-xs ${color}`}>{status}</span>;
}
