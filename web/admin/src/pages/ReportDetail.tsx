import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api';

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['report', id],
    queryFn: () => api.getReport(id!),
    enabled: !!id,
    // Refetch while pending so the worker's transitions surface without
    // a manual page reload.
    refetchInterval: (q) => {
      const s = q.state.data?.row_count;
      return s === 0 ? 3_000 : false;
    },
  });

  if (!id) return <div>Missing report id.</div>;
  if (isLoading) return <div>Loading report…</div>;
  if (error) return <div className="text-red-600">Failed to load report.</div>;
  if (!data) return null;

  return (
    <div>
      <Link to="/reports" className="text-blue-700 hover:underline text-sm">
        ← back to reports
      </Link>
      <h1 className="text-2xl font-bold mt-2 mb-4">
        Report <span className="font-mono">{data.report_id}</span>
      </h1>
      <div className="bg-white rounded shadow p-4 space-y-2 text-sm">
        <div>
          <span className="text-slate-500">Kind: </span>
          {data.kind}
        </div>
        <div>
          <span className="text-slate-500">Period: </span>
          {data.start_date} → {data.end_date}
        </div>
        <div>
          <span className="text-slate-500">Generated at: </span>
          {new Date(data.generated_at).toLocaleString()}
        </div>
        <div>
          <span className="text-slate-500">Rows: </span>
          {data.row_count.toLocaleString()}
        </div>
        <button
          onClick={() => refetch()}
          className="mt-2 text-xs underline text-blue-700"
        >
          Refresh
        </button>
      </div>
    </div>
  );
}
