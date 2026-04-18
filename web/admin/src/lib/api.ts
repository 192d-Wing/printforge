// Thin fetch wrapper that attaches the current session's JWT and
// surfaces server errors as typed rejections. The token is pulled from
// auth.ts — this module stays dependency-free so it can be swapped for
// a streaming client (EventSource / WebSocket) later without rewriting
// every caller.

import { getToken } from './auth';
import type {
  Alert,
  AlertListResponse,
  DashboardKpis,
  FleetStatusSummary,
  FleetViewResponse,
  JobViewResponse,
  QuotaStatusResponse,
  Role,
  ReportMetadata,
  ReportRequest,
  UserListResponse,
  UserSummary,
} from './types';

export class ApiError extends Error {
  status: number;
  body: string;

  constructor(status: number, body: string) {
    super(`API ${status}: ${body.slice(0, 200)}`);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    const body = await response.text();
    throw new ApiError(response.status, body);
  }
  // Some admin endpoints return an empty body (e.g., DELETE).
  const text = await response.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export const api = {
  dashboard: () => request<DashboardKpis>('/api/v1/admin/dashboard/kpis'),

  fleetOverview: () => request<FleetStatusSummary>('/api/v1/admin/fleet/overview'),
  fleetPrinters: () => request<FleetViewResponse>('/api/v1/admin/fleet/printers'),

  jobs: () => request<JobViewResponse>('/api/v1/admin/jobs'),

  users: () => request<UserListResponse>('/api/v1/admin/users'),
  userQuota: (edipi: string) =>
    request<QuotaStatusResponse>(`/api/v1/admin/users/${encodeURIComponent(edipi)}/quota`),
  updateUserRoles: (edipi: string, roles: Role[], reason: string) =>
    request<UserSummary>(`/api/v1/admin/users/${encodeURIComponent(edipi)}/roles`, {
      method: 'PATCH',
      body: JSON.stringify({ user_id: edipi, roles, reason }),
    }),

  alerts: () => request<AlertListResponse>('/api/v1/admin/alerts'),
  acknowledgeAlert: (id: string) =>
    request<Alert>(`/api/v1/admin/alerts/${id}/acknowledge`, { method: 'POST' }),

  generateReport: (req: ReportRequest) =>
    request<ReportMetadata>('/api/v1/admin/reports/generate', {
      method: 'POST',
      body: JSON.stringify(req),
    }),
  getReport: (id: string) => request<ReportMetadata>(`/api/v1/admin/reports/${id}`),
};
