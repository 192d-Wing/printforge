import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export default function Jobs() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['jobs'],
    queryFn: api.jobs,
    refetchInterval: 10_000,
  });

  if (isLoading) return <div>Loading jobs…</div>;
  if (error) return <div className="text-red-600">Failed to load jobs.</div>;
  if (!data) return null;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Jobs</h1>
      <div className="bg-white rounded shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="p-2">Submitted</th>
              <th className="p-2">Owner</th>
              <th className="p-2">Document</th>
              <th className="p-2">Status</th>
              <th className="p-2">Pages</th>
              <th className="p-2">Copies</th>
              <th className="p-2">Duplex</th>
              <th className="p-2">Color</th>
              <th className="p-2">Site</th>
              <th className="p-2">Target</th>
              <th className="p-2">Cost center</th>
            </tr>
          </thead>
          <tbody>
            {data.jobs.map((j) => (
              <tr key={j.job_id} className="border-t">
                <td className="p-2">
                  {new Date(j.submitted_at).toLocaleString()}
                </td>
                <td className="p-2">{j.owner_display_name}</td>
                <td className="p-2">{j.document_name}</td>
                <td className="p-2">{j.status}</td>
                <td className="p-2">{j.page_count ?? '—'}</td>
                <td className="p-2">{j.copies}</td>
                <td className="p-2">
                  {j.sides === 'OneSided' ? 'No' : 'Yes'}
                </td>
                <td className="p-2">{j.color}</td>
                <td className="p-2">{j.site_id || '—'}</td>
                <td className="p-2 font-mono">{j.target_printer ?? '—'}</td>
                <td className="p-2 text-xs">
                  {j.cost_center.code} {j.cost_center.name}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="p-2 text-xs text-slate-500 border-t">
          {data.total_count} jobs total
        </div>
      </div>
    </div>
  );
}
