const CVE_ID = /^CVE-\d{4}-\d+$/i;
const ADVISORY_ID = /^(?:RLSA|RLBA|RLEA|RHSA|RHBA|RHEA)-\d{4}:\d+$/i;

export { ADVISORY_ID, CVE_ID };

export function routeQuery(raw: string): string | null {
  const q = raw.trim();
  if (!q) return null;
  if (CVE_ID.test(q)) return `/cves/${q.toUpperCase()}`;
  if (ADVISORY_ID.test(q)) return `/${q.toUpperCase()}`;
  return `/search?q=${encodeURIComponent(q)}`;
}
