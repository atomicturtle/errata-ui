/** In-app copy for metric (i) hints — kept local, not external docs. */

export type MetricHelpId = "epss" | "exploit_maturity";

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
};
