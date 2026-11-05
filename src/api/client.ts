import type {
  V2AdvisoryDetailResponse,
  V2AdvisoryListResponse,
} from "./types";
import type { NvdCveListResponse } from "../lib/nvd";

const BASE_PATH = "/api";

export interface ListAdvisoriesParams {
  page?: number;
  limit?: number;
  keyword?: string;
  product?: string;
  before?: Date;
  after?: Date;
  severity?: string;
  type?: string;
  fetchRelated?: boolean;
}

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw res;
  }
  return res.json() as Promise<T>;
}

export function listAdvisories(
  params: ListAdvisoriesParams
): Promise<V2AdvisoryListResponse> {
  const searchParams = new URLSearchParams();

  if (params.page !== undefined)
    searchParams.set("page", String(params.page));
  if (params.limit !== undefined)
    searchParams.set("limit", String(params.limit));
  if (params.keyword) searchParams.set("filters.keyword", params.keyword);
  if (params.product) searchParams.set("filters.product", params.product);
  if (params.before)
    searchParams.set("filters.before", params.before.toISOString());
  if (params.after)
    searchParams.set("filters.after", params.after.toISOString());
  if (params.severity)
    searchParams.set("filters.severity", params.severity);
  if (params.type) searchParams.set("filters.type", params.type);
  if (params.fetchRelated !== undefined)
    searchParams.set(
      "filters.fetchRelated",
      String(params.fetchRelated)
    );

  return apiFetch<V2AdvisoryListResponse>(
    `${BASE_PATH}/v2/advisories?${searchParams.toString()}`
  );
}

export function getAdvisory(id: string): Promise<V2AdvisoryDetailResponse> {
  return apiFetch<V2AdvisoryDetailResponse>(
    `${BASE_PATH}/v2/advisories/${encodeURIComponent(id)}`
  );
}

export function getRSSUrl(): string {
  return `${BASE_PATH}/v2/advisories:rss`;
}

/** Apollo's /api/v3/nvd/cves rejects requests with more IDs than this. */
const NVD_IDS_PER_REQUEST = 100;

function fetchNvdBatch(ids: string[]): Promise<NvdCveListResponse> {
  const params = new URLSearchParams();
  params.set("ids", ids.join(","));
  return apiFetch<NvdCveListResponse>(
    `${BASE_PATH}/v3/nvd/cves?${params.toString()}`
  );
}

/** Batch-fetch NVD enrichment for CVE IDs already synced into Apollo. */
export async function getNvdCves(ids: string[]): Promise<NvdCveListResponse> {
  const unique = [...new Set(ids.filter(Boolean))];
  const batches: string[][] = [];
  for (let start = 0; start < unique.length; start += NVD_IDS_PER_REQUEST) {
    batches.push(unique.slice(start, start + NVD_IDS_PER_REQUEST));
  }
  const responses = await Promise.all(batches.map(fetchNvdBatch));
  return {
    items: responses.flatMap((response) => response.items),
    missing: responses.flatMap((response) => response.missing),
  };
}
