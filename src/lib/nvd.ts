export interface NvdCve {
  cve_id: string;
  description?: string | null;
  cvss_v2_score?: string | null;
  cvss_v2_vector?: string | null;
  cvss_v3_score?: string | null;
  cvss_v3_vector?: string | null;
  cvss_v4_score?: string | null;
  cvss_v4_vector?: string | null;
  cwe?: string | null;
  references?: Array<{ url?: string; source?: string; tags?: string[] }> | null;
  epss_score?: string | null;
  epss_percentile?: string | null;
  exploit_maturity?: string | null;
  exploit_count?: number;
  kev_listed?: boolean;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  kev_ransomware?: string | null;
  cpes?: string[] | null;
  published_at?: string | null;
  last_modified_at?: string | null;
  fetched_at?: string | null;
}

export interface NvdCveListResponse {
  items: NvdCve[];
  missing: string[];
}

export type CvssSeverityLabel =
  | "NONE"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export function cvssScoreToSeverity(score: number | null): CvssSeverityLabel {
  if (score === null || Number.isNaN(score)) return "NONE";
  if (score === 0) return "NONE";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  return "CRITICAL";
}

export function parseScore(raw?: string | null): number | null {
  if (raw === undefined || raw === null || raw === "") return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

/** Decode CVSS v3.x vector metrics into display labels. */
export function parseCvss3Metrics(
  vector?: string | null
): Record<string, string> {
  if (!vector) return {};
  const parts = vector.split("/");
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(":");
    if (k && v && k !== "CVSS") map[k] = v;
  }

  const av: Record<string, string> = {
    N: "Network",
    A: "Adjacent",
    L: "Local",
    P: "Physical",
  };
  const ac: Record<string, string> = { L: "Low", H: "High" };
  const pr: Record<string, string> = {
    N: "None",
    L: "Low",
    H: "High",
  };
  const ui: Record<string, string> = { N: "None", R: "Required" };
  const scope: Record<string, string> = {
    U: "Unchanged",
    C: "Changed",
  };
  const cia: Record<string, string> = {
    N: "None",
    L: "Low",
    H: "High",
  };

  return {
    "Attack Vector": av[map.AV] ?? map.AV ?? "—",
    "Attack Complexity": ac[map.AC] ?? map.AC ?? "—",
    "Privileges Required": pr[map.PR] ?? map.PR ?? "—",
    "User Interaction": ui[map.UI] ?? map.UI ?? "—",
    Scope: scope[map.S] ?? map.S ?? "—",
    "Confidentiality Impact": cia[map.C] ?? map.C ?? "—",
    "Integrity Impact": cia[map.I] ?? map.I ?? "—",
    "Availability Impact": cia[map.A] ?? map.A ?? "—",
  };
}

export function severityColor(label: CvssSeverityLabel): string {
  switch (label) {
    case "NONE":
      return "gray.400";
    case "LOW":
      return "green.400";
    case "MEDIUM":
      return "yellow.400";
    case "HIGH":
      return "orange.400";
    case "CRITICAL":
      return "red.500";
  }
}

/** Marker position 0–100 for the severity gauge. */
export function severityGaugePercent(score: number | null): number {
  if (score === null) return 0;
  return Math.min(100, Math.max(0, (score / 10) * 100));
}

export function nvdDetailUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
}

/** MITRE CWE definition URL for IDs like ``CWE-22`` or ``22``. */
export function cweDetailUrl(cweId: string): string | null {
  const m = cweId.trim().match(/^(?:CWE-)?(\d+)$/i);
  if (!m) return null;
  return `https://cwe.mitre.org/data/definitions/${m[1]}.html`;
}

export function splitCweIds(raw?: string | null): string[] {
  if (!raw) return [];
  return raw
    .split(/[,;/]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function pickPrimaryNvd(items: NvdCve[]): NvdCve | undefined {
  if (!items.length) return undefined;
  return [...items].sort((a, b) => {
    const sa = parseScore(a.cvss_v3_score) ?? parseScore(a.cvss_v2_score) ?? -1;
    const sb = parseScore(b.cvss_v3_score) ?? parseScore(b.cvss_v2_score) ?? -1;
    return sb - sa;
  })[0];
}

/** CVSS temporal / Atomic maturity ladder (1–5 filled dots). */
export const EXPLOIT_MATURITY_LEVELS = [
  "Unproven",
  "Proof-of-Concept",
  "Functional",
  "High",
] as const;

export function exploitMaturityRank(label?: string | null): number {
  if (!label) return 0;
  const n = label.trim().toLowerCase();
  if (
    n === "unproven" ||
    n === "unreported" ||
    n === "u" ||
    n === "not defined" ||
    n === "x"
  ) {
    return 1;
  }
  if (n.includes("proof") || n === "poc" || n === "p") return 2;
  if (n.includes("functional") || n === "f") return 3;
  if (
    n === "high" ||
    n === "h" ||
    n.includes("weapon") ||
    n.includes("attacked") ||
    n === "a"
  ) {
    return 4;
  }
  return 1;
}
