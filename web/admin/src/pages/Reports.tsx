import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { ReportFormat, ReportKind, ReportMetadata } from '../lib/types';

const KINDS: ReportKind[] = [
  'Chargeback',
  'Utilization',
  'QuotaCompliance',
  'WasteReduction',
];

export default function Reports() {
  const today = new Date().toISOString().slice(0, 10);
  const firstOfMonth = today.slice(0, 8) + '01';

  const [kind, setKind] = useState<ReportKind>('Chargeback');
  const [format, setFormat] = useState<ReportFormat>('Csv');
  const [startDate, setStartDate] = useState(firstOfMonth);
  const [endDate, setEndDate] = useState(today);
  const [siteId, setSiteId] = useState('');
  const [recent, setRecent] = useState<ReportMetadata[]>([]);

  const mutation = useMutation({
    mutationFn: () =>
      api.generateReport({
        kind,
        format,
        start_date: startDate,
        end_date: endDate,
        site_id: siteId.trim() || null,
      }),
    onSuccess: (meta) => setRecent((r) => [meta, ...r].slice(0, 20)),
  });

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Reports</h1>

      <section className="bg-white rounded shadow p-4 mb-6">
        <h2 className="font-semibold mb-3">Generate</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
          <label className="flex flex-col">
            <span className="text-xs text-slate-500">Kind</span>
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as ReportKind)}
              className="border rounded p-1"
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col">
            <span className="text-xs text-slate-500">Format</span>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as ReportFormat)}
              className="border rounded p-1"
            >
              <option value="Csv">CSV</option>
              <option value="Json">JSON</option>
            </select>
          </label>
          <label className="flex flex-col">
            <span className="text-xs text-slate-500">Start</span>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="border rounded p-1"
            />
          </label>
          <label className="flex flex-col">
            <span className="text-xs text-slate-500">End</span>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="border rounded p-1"
            />
          </label>
          <label className="flex flex-col">
            <span className="text-xs text-slate-500">Site (blank = all)</span>
            <input
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
              className="border rounded p-1"
            />
          </label>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="px-4 py-2 bg-slate-900 text-white rounded hover:bg-slate-800 disabled:opacity-50"
          >
            {mutation.isPending ? 'Enqueueing…' : 'Generate report'}
          </button>
          {mutation.error && (
            <span className="text-red-600 text-sm">
              {(mutation.error as Error).message}
            </span>
          )}
        </div>
      </section>

      <section className="bg-white rounded shadow p-4">
        <h2 className="font-semibold mb-3">Recently enqueued</h2>
        {recent.length === 0 && (
          <div className="text-slate-500 text-sm">
            None yet in this session. Reports generate asynchronously; check
            status via the detail link.
          </div>
        )}
        <ul className="divide-y">
          {recent.map((r) => (
            <li key={r.report_id} className="py-2 flex justify-between">
              <div>
                <Link
                  to={`/reports/${r.report_id}`}
                  className="text-blue-700 hover:underline font-mono text-sm"
                >
                  {r.report_id}
                </Link>
                <span className="ml-2 text-xs text-slate-500">
                  {r.kind} · {r.start_date} → {r.end_date}
                </span>
              </div>
              <div className="text-xs text-slate-500">
                {r.row_count} rows
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
