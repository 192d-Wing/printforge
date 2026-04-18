// Mirrors the wire types from pf-admin-ui. Kept narrow on purpose — new
// fields on the Rust side need a matching entry here, and CI
// type-checking will catch drift at build time.

export type Role =
  | 'User'
  | 'Auditor'
  | 'FleetAdmin'
  | { SiteAdmin: string };

export interface SiteId {
  0: string;
}

export interface DashboardKpis {
  computed_at: string;
  total_printers: number;
  online_printers: number;
  error_printers: number;
  maintenance_printers: number;
  held_jobs: number;
  active_jobs: number;
  monthly_pages: number;
  monthly_cost_cents: number;
  active_alerts: number;
}

export type PrinterStatus =
  | 'Online'
  | 'Offline'
  | 'Error'
  | 'Maintenance'
  | 'Printing';

export interface FleetPrinterSummary {
  printer_id: string;
  display_name: string;
  site_id: string;
  location: string;
  model: { vendor: string; model: string };
  status: PrinterStatus;
  supply_levels: {
    toner_k: number;
    toner_c: number;
    toner_m: number;
    toner_y: number;
    paper: number;
  };
  last_seen: string;
  health_score: number;
}

export interface FleetViewResponse {
  printers: FleetPrinterSummary[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface FleetStatusSummary {
  online: number;
  offline: number;
  error: number;
  maintenance: number;
  printing: number;
}

export type JobStatus =
  | 'Held'
  | 'Waiting'
  | 'Releasing'
  | 'Printing'
  | 'Completed'
  | 'Failed'
  | 'Purged';

export interface JobSummary {
  job_id: string;
  owner_display_name: string;
  document_name: string;
  status: JobStatus;
  page_count: number | null;
  copies: number;
  sides: 'OneSided' | 'TwoSidedLongEdge' | 'TwoSidedShortEdge';
  color: 'Color' | 'Grayscale' | 'AutoDetect';
  media: 'Letter' | 'Legal' | 'Ledger' | 'A4' | 'A3';
  cost_center: { code: string; name: string };
  site_id: string;
  target_printer: string | null;
  submitted_at: string;
  released_at: string | null;
  completed_at: string | null;
}

export interface JobViewResponse {
  jobs: JobSummary[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface UserSummary {
  user_id: string;
  display_name: string;
  organization: string;
  site_id: string;
  roles: Role[];
  active: boolean;
  quota: {
    limit: number;
    used: number;
    color_limit: number;
    color_used: number;
  } | null;
  last_login: string | null;
  provisioned_at: string;
}

export interface UserListResponse {
  users: UserSummary[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface QuotaStatusResponse {
  edipi: string;
  page_limit: number;
  pages_used: number;
  pages_remaining: number;
  color_page_limit: number;
  color_pages_used: number;
  color_pages_remaining: number;
  burst_pages_used: number;
  burst_limit: number;
  burst_pages_remaining: number;
  period_start: string;
  period_end: string;
}

export type AlertSeverity = 'Info' | 'Warning' | 'Critical';
export type AlertCategory =
  | 'PrinterStatus'
  | 'SupplyLow'
  | 'Firmware'
  | 'Security'
  | 'Quota'
  | 'CacheNode';
export type AlertState = 'Active' | 'Acknowledged' | 'Resolved';

export interface Alert {
  alert_id: string;
  severity: AlertSeverity;
  category: AlertCategory;
  state: AlertState;
  title: string;
  description: string;
  site_id: string;
  printer_id: string | null;
  created_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
}

export interface AlertListResponse {
  alerts: Alert[];
  total_count: number;
  page: number;
  page_size: number;
}

export type ReportKind =
  | 'Chargeback'
  | 'Utilization'
  | 'QuotaCompliance'
  | 'WasteReduction';

export type ReportFormat = 'Csv' | 'Json';

export interface ReportMetadata {
  report_id: string;
  kind: ReportKind;
  generated_at: string;
  start_date: string;
  end_date: string;
  row_count: number;
}

export interface ReportRequest {
  kind: ReportKind;
  format: ReportFormat;
  start_date: string;
  end_date: string;
  site_id: string | null;
}
