/** In-app copy for metric (i) hints — kept local, not external docs. */

export type MetricHelpId =
  | "epss"
  | "exploit_maturity"
  | "cvss_v3"
  | "vendor_severity"
  | "rocky_status"
  | "cwe"
  | "kev";

export interface MetricHelpEntry {
  title: string;
  summary: string;
  bullets: string[];
  note?: string;
}

export const METRIC_HELP: Record<MetricHelpId, MetricHelpEntry> = {
  epss: {
    title: "EPSS",
    summary:
      "Exploit Prediction Scoring System estimates how likely a CVE is to be exploited in the wild in the next 30 days.",
    bullets: [
      "Score is a probability from 0 to 1 (shown here as a percent). Higher means more likely exploitation activity soon.",
      "It is not severity — that is CVSS. A critical CVE can have a low EPSS, and a moderate CVE can have a high EPSS.",
      "It is not proof of active exploitation — CISA KEV and exploit maturity speak more directly to observed or available exploits.",
      "Scores change over time as FIRST.org updates the model and threat signals.",
    ],
    note: "Blank means we do not yet have an EPSS value for this CVE in enrichment data.",
  },
  exploit_maturity: {
    title: "Exploit Maturity",
    summary:
      "Describes how mature known exploit techniques or code are for this vulnerability — from no public exploit signal up to widely usable or weaponized exploits.",
    bullets: [
      "Unproven / Unreported — no known public proof-of-concept or reported exploitation attempts.",
      "Proof-of-Concept — public PoC code exists; no reliable reports of real-world attacks yet.",
      "Functional — working exploit code is available that can reliably demonstrate the issue.",
      "High / Attacked — exploits are refined, widely available (for example in toolkits), and/or attacks have been reported in the wild.",
    ],
    note: "This is about exploit availability and observed use, not CVSS base severity or EPSS probability.",
  },
  cvss_v3: {
    title: "CVSS v3",
    summary:
      "Common Vulnerability Scoring System version 3 rates the intrinsic severity of a CVE from 0.0 to 10.0.",
    bullets: [
      "Low is 0.1–3.9, Medium is 4.0–6.9, High is 7.0–8.9, and Critical is 9.0–10.0.",
      "This score is not the vendor severity. Rocky’s advisory label can differ from this band.",
      "The vector and the individual metrics are in Technical details.",
    ],
    note: "A dash means no CVSS v3 score is stored.",
  },
  vendor_severity: {
    title: "Vendor severity",
    summary: "The severity Rocky Linux published on the advisory that names a fix for this CVE.",
    bullets: [
      "It comes from the advisory, not from the CVSS score.",
      "Red Hat Important is shown as High. Moderate or Medium is shown as Medium.",
      "Unknown means no matching record lists a fix, so there is no advisory severity to show.",
    ],
    note: "It can disagree with the CVSS band on this page. Both are shown on purpose.",
  },
  rocky_status: {
    title: "Rocky Linux status",
    summary: "A summary of the remediation records for this CVE on Rocky Linux.",
    bullets: [
      "Fix listed in advisory means every matching record names a fixed source build. That is not an independently verified copy in a repository.",
      "In research means every matching record is still open.",
      "Not shipped means no fixed build is recorded. That does not mean the package is unaffected.",
      "Not affected means Rocky repository metadata does not contain the vulnerable component, and no Rocky or Red Hat advisory lists this CVE.",
      "Mixed means the records do not all have the same status. The table lists each one.",
    ],
  },
  cwe: {
    title: "CWE",
    summary:
      "Common Weakness Enumeration. A CWE id names the class of flaw, such as a buffer overflow or an injection bug.",
    bullets: [
      "Taken from NVD when NVD records one, otherwise from the Rocky advisory.",
      "The link opens the MITRE definition for that id.",
    ],
    note: "Unavailable means no CWE is stored.",
  },
  kev: {
    title: "CISA KEV",
    summary:
      "The CISA Known Exploited Vulnerabilities catalog lists CVEs with evidence of exploitation in the wild.",
    bullets: [
      "Listed means the stored NVD record includes this CVE in that catalog.",
      "Not listed means that record does not. It is not a claim that the CVE has never been exploited.",
      "This is separate from CVSS severity and from the EPSS probability.",
    ],
    note: "KEV is read only from NVD. It is not inferred from a Rocky advisory.",
  },
};
