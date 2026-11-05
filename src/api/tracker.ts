export interface TrackerMeta {
  total: number;
  page: number;
  limit: number;
}

export interface CveRow {
  cve: string;
  product: string;
  component: string | null;
  version: string | null;
  epoch?: string | null;
  severity: string;
  status: string;
  statusCode?: string | null;
  justification?: string | null;
  published: string | null;
  cvssV3Score?: string | null;
  reason?: string | null;
  advisory?: string | null;
}

export interface CveGroup {
  cve: string;
  description: string | null;
  vendorSeverity: string | null;
  vendorSeverityMixed: boolean;
  cvssSeverity: string | null;
  cvssV3Score: string | null;
  releases: string[];
  packageCount: number;
  status: string;
  statusCode?: string | null;
  published: string | null;
  records: CveRow[];
}

export interface FixRow {
  advisory: string;
  product: string;
  component: string | null;
  version: string | null;
  severity: string;
  type: string;
  published: string | null;
  title: string | null;
}

export interface TechnologyRow {
  product: string;
  component: string;
  version: string | null;
  advisoryCount: number;
  eolAt: string | null;
  published: string | null;
}

export interface ProductRow {
  name: string;
  eolAt: string | null;
}

export interface FixRelease {
  product: string;
  component: string | null;
  version: string | null;
  updateCommand: string;
  packages: string[];
  ovalUrl: string | null;
}

export interface FixDetail {
  advisory: string;
  title: string | null;
  description: string | null;
  severity: string;
  type: string;
  published: string | null;
  changelog: string[];
  cves: string[];
  csafUrl: string;
  releases: FixRelease[];
}

export interface CveAdvisory {
  advisory: string;
  title: string | null;
  severity: string;
  published: string | null;
  products: string[];
}

export interface CveContext {
  product: string;
  component: string | null;
  version: string | null;
  status: string;
  reason: string | null;
  justification?: string | null;
  advisory: string | null;
  advisories: CveAdvisory[];
}

export interface CveDetail {
  cve: string;
  description: string | null;
  cwe: string | null;
  severity: string;
  cvssV3Score: string | null;
  cvssV3Vector: string | null;
  cvssV2Score: string | null;
  epssScore: string | null;
  epssPercentile: string | null;
  exploitMaturity: string | null;
  kevListed: boolean;
  published: string | null;
  updated: string | null;
  references: string[];
  nvdUrl: string;
  vexUrl: string;
  sources?: {
    description: "nvd" | "advisory" | null;
    cwe: "nvd" | "advisory" | null;
    cvss: "nvd" | "advisory" | null;
    epss?: "nvd" | "first" | null;
    exploitMaturity?: "nvd" | "vector" | null;
    advisory: string | null;
  };
  contexts: CveContext[];
}

export interface Page<T> {
  data: T[];
  meta: TrackerMeta;
}

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw res;
  }
  return res.json() as Promise<T>;
}

export function trackerUrl(path: string, params: URLSearchParams): string {
  const query = params.toString();
  return query ? `/api/v3/tracker${path}?${query}` : `/api/v3/tracker${path}`;
}

export function listTrackerCves(params: URLSearchParams): Promise<Page<CveRow>> {
  return apiFetch(trackerUrl("/cves", params));
}

export function listTrackerCveGroups(params: URLSearchParams): Promise<Page<CveGroup>> {
  return apiFetch(trackerUrl("/cves", params));
}

export function getTrackerCve(
  cve: string,
  params: URLSearchParams
): Promise<CveDetail> {
  return apiFetch(trackerUrl(`/cves/${encodeURIComponent(cve)}`, params));
}

export function listTrackerFixes(params: URLSearchParams): Promise<Page<FixRow>> {
  return apiFetch(trackerUrl("/fixes", params));
}

export function getTrackerFix(name: string): Promise<FixDetail> {
  return apiFetch(`/api/v3/tracker/fixes/${encodeURIComponent(name)}`);
}

export function listTechnologies(
  params: URLSearchParams
): Promise<Page<TechnologyRow>> {
  return apiFetch(trackerUrl("/technologies", params));
}

export function listTrackerProducts(): Promise<{ data: ProductRow[] }> {
  return apiFetch("/api/v3/tracker/products");
}

export function exportUrl(path: string, params: URLSearchParams): string {
  const copy = new URLSearchParams(params);
  copy.delete("page");
  copy.delete("limit");
  copy.delete("sort_column");
  copy.delete("sort_order");
  copy.delete("advisory");
  return trackerUrl(path, copy);
}
