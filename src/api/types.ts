export type AdvisoryType =
  | "TYPE_SECURITY"
  | "TYPE_BUGFIX"
  | "TYPE_ENHANCEMENT";

export type AdvisorySeverity =
  | "SEVERITY_UNKNOWN"
  | "SEVERITY_LOW"
  | "SEVERITY_MODERATE"
  | "SEVERITY_IMPORTANT"
  | "SEVERITY_CRITICAL";

export interface V2Fix {
  ticket: string;
  sourceBy: string;
  sourceLink: string;
  description: string;
}

export interface V2CVE {
  name: string;
  sourceBy: string;
  sourceLink: string;
  cvss3ScoringVector: string;
  cvss3BaseScore: string;
  cwe: string;
}

export interface V2RPMs {
  nvras: string[];
  repositories?: string[];
}

export interface V2Source {
  name: string;
  url: string;
  vendor: string;
  license: string;
  licenseUrl: string;
}

export interface V2Advisory {
  id?: number;
  publishedAt?: string;
  rockyPublishedAt?: string | null;
  name?: string;
  synopsis?: string;
  description?: string;
  type?: AdvisoryType;
  severity?: AdvisorySeverity;
  shortCode?: string;
  topic?: string;
  solution?: string | null;
  affectedProducts?: string[];
  fixes?: V2Fix[];
  cves?: V2CVE[];
  references?: string[];
  rpms?: Record<string, V2RPMs>;
  rebootSuggested?: boolean;
  restartSuggested?: boolean;
  buildReferences?: string[];
  source?: V2Source | null;
}

export interface V2AdvisoryListResponse {
  advisories: V2Advisory[];
  total: number;
  page: number;
  size: number;
  lastUpdated?: string;
}

export interface V2AdvisoryDetailResponse {
  advisory: V2Advisory;
}

export const AdvisoryTypeEnum = {
  Security: "TYPE_SECURITY",
  "Bug Fix": "TYPE_BUGFIX",
  Enhancement: "TYPE_ENHANCEMENT",
} as const;

export type AdvisoryTypeFilterKey = keyof typeof AdvisoryTypeEnum;

export const AdvisorySeverityEnum = {
  Low: "SEVERITY_LOW",
  Moderate: "SEVERITY_MODERATE",
  Important: "SEVERITY_IMPORTANT",
  Critical: "SEVERITY_CRITICAL",
} as const;

export type AdvisorySeverityFilterKey = keyof typeof AdvisorySeverityEnum;
