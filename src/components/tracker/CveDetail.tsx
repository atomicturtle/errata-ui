import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ChevronUpIcon,
  CopyIcon,
  ExternalLinkIcon,
} from "@chakra-ui/icons";
import {
  Badge,
  Box,
  Button,
  Collapse,
  Flex,
  Grid,
  Heading,
  HStack,
  IconButton,
  Link,
  SimpleGrid,
  Stack,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  useColorModeValue,
} from "@chakra-ui/react";
import { Fragment, useEffect, useState, type ReactNode } from "react";
import { Link as RouterLink, useParams, useSearchParams } from "react-router-dom";

import { getAdvisory } from "../../api/client";
import { getTrackerCve, type CveContext, type CveDetail } from "../../api/tracker";
import type { V2Advisory, V2RPMs } from "../../api/types";
import { cvssScoreToSeverity, parseCvss3Metrics, parseScore } from "../../lib/nvd";
import { safeHttpUrl } from "../../lib/safeHttpUrl";
import { COLOR_RESF_GREEN } from "../../styles";
import { MetricInfoHint } from "../MetricInfoHint";
import { ErrataTitleShield } from "../VulnBadges";
import { fixStatusLabel } from "./Filters";

interface ParsedRpm {
  nevra: string;
  name: string;
  epoch: string;
  version: string;
  release: string;
  arch: string;
}

const ARCH_ORDER = ["x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch", "riscv64"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function band(score: string | null | undefined): string | null {
  const label = cvssScoreToSeverity(parseScore(score));
  if (label === "NONE") return null;
  return label[0] + label.slice(1).toLowerCase();
}

function severityScheme(severity: string | null): string {
  if (severity === "Critical") return "red";
  if (severity === "High") return "orange";
  if (severity === "Medium") return "yellow";
  if (severity === "Low") return "green";
  return "gray";
}

function isSource(nevra: string): boolean {
  return nevra.endsWith(".src.rpm") || nevra.endsWith(".src");
}

function isDebug(nevra: string): boolean {
  return nevra.includes("-debuginfo-") || nevra.includes("-debugsource-");
}

function parseRpm(nevra: string): ParsedRpm | null {
  const match = nevra.replace(/\.rpm$/, "").match(/^(.+)-(\d+):([^-]+)-([^-]+)\.([^.]+)$/);
  if (!match) return null;
  return {
    nevra,
    name: match[1],
    epoch: match[2],
    version: match[3],
    release: match[4],
    arch: match[5],
  };
}

function evrOf(rpm: ParsedRpm): string {
  return `${rpm.epoch}:${rpm.version}-${rpm.release}`;
}

function displayEvr(rpm: ParsedRpm): string {
  if (rpm.epoch === "0") return `${rpm.version}-${rpm.release}`;
  return evrOf(rpm);
}

function sameEvr(left: ParsedRpm, right: ParsedRpm): boolean {
  return evrOf(left) === evrOf(right);
}

function nameMatch(source: ParsedRpm, binary: ParsedRpm): boolean {
  return binary.name === source.name || binary.name.startsWith(`${source.name}-`);
}

function advisoryNames(detail: CveDetail): string[] {
  const names = new Set<string>();
  for (const item of detail.contexts) {
    if (item.advisory) names.add(item.advisory);
    for (const advisory of item.advisories) names.add(advisory.advisory);
  }
  return [...names];
}

function packagesFor(advisory: V2Advisory | undefined, product: string): V2RPMs | null {
  return advisory?.rpms?.[product] ?? null;
}

function matchingSources(nvras: string[], component: string | null): ParsedRpm[] {
  return nvras
    .filter(isSource)
    .map(parseRpm)
    .filter((rpm): rpm is ParsedRpm => rpm !== null && (!component || rpm.name === component));
}

function assignBinaries(sources: ParsedRpm[], binaries: ParsedRpm[]) {
  const groups = sources.map((source) => ({ source, binaries: [] as ParsedRpm[] }));
  const unmatched: ParsedRpm[] = [];
  for (const binary of binaries) {
    const named = groups.filter((group) => sameEvr(group.source, binary) && nameMatch(group.source, binary));
    if (named.length === 1) {
      named[0].binaries.push(binary);
      continue;
    }
    const byEvr = groups.filter((group) => sameEvr(group.source, binary));
    if (named.length === 0 && byEvr.length === 1) {
      byEvr[0].binaries.push(binary);
      continue;
    }
    unmatched.push(binary);
  }
  return { groups, unmatched };
}

function byArch(rpms: ParsedRpm[]): Array<[string, ParsedRpm[]]> {
  const grouped = new Map<string, ParsedRpm[]>();
  for (const rpm of rpms) {
    const list = grouped.get(rpm.arch) ?? [];
    list.push(rpm);
    grouped.set(rpm.arch, list);
  }
  return [...grouped.entries()].sort((left, right) => {
    const ai = ARCH_ORDER.indexOf(left[0]);
    const bi = ARCH_ORDER.indexOf(right[0]);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi) || left[0].localeCompare(right[0]);
  });
}

function formatDay(value: string | null | undefined): string {
  if (!value) return "unavailable";
  const match = value.slice(0, 10).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return value;
  return `${MONTHS[Number(match[2]) - 1]} ${Number(match[3])}, ${match[1]}`;
}

function copyText(value: string): Promise<void> {
  return navigator.clipboard.writeText(value).catch(() => {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    if (!ok) throw new Error("copy failed");
  });
}

function referenceLabel(url: string): string {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.replace(/^www\./, "");
    const tail = parsed.pathname.split("/").filter(Boolean).pop();
    if (!tail || tail.length > 60) return host;
    return `${host} — ${decodeURIComponent(tail)}`;
  } catch {
    return url;
  }
}

function cweIds(value: string | null): string[] {
  if (!value) return [];
  return value.split(/[,\s]+/).filter((part) => /^CWE-\d+$/i.test(part));
}

export function CveDetailPage() {
  const { cveId = "" } = useParams();
  const [params] = useSearchParams();
  const [detail, setDetail] = useState<CveDetail>();
  const [advisories, setAdvisories] = useState<Record<string, V2Advisory>>({});
  const [error, setError] = useState(false);
  const [showDescription, setShowDescription] = useState(false);
  const cardBg = useColorModeValue("white", "#121820");
  const insetBg = useColorModeValue("gray.50", "#0d131a");
  const borderColor = useColorModeValue("gray.200", "whiteAlpha.300");
  const linkBlue = useColorModeValue("blue.600", "blue.300");
  const muted = useColorModeValue("gray.600", "gray.400");

  useEffect(() => {
    document.title = cveId || "CVE";
    const query = new URLSearchParams();
    for (const key of ["product", "component", "version"]) {
      const value = params.get(key);
      if (value) query.set(key, value);
    }
    let cancelled = false;
    setError(false);
    setAdvisories({});
    setShowDescription(false);
    getTrackerCve(cveId, query)
      .then((result) => {
        if (!cancelled) setDetail(result);
      })
      .catch(() => {
        if (!cancelled) setError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [cveId, params]);

  useEffect(() => {
    if (!detail) return;
    let cancelled = false;
    Promise.all(
      advisoryNames(detail).map(async (name) => {
        try {
          const result = await getAdvisory(name);
          return [name, result.advisory] as const;
        } catch {
          return [name, null] as const;
        }
      })
    ).then((pairs) => {
      if (cancelled) return;
      const next: Record<string, V2Advisory> = {};
      for (const [name, advisory] of pairs) {
        if (advisory) next[name] = advisory;
      }
      setAdvisories(next);
    });
    return () => {
      cancelled = true;
    };
  }, [detail]);

  if (error) {
    return (
      <Box p={4}>
        <Link as={RouterLink} to="/cves" color={linkBlue}>
          CVEs
        </Link>
        <Text mt={4}>This CVE is not in the Rocky tracker.</Text>
      </Box>
    );
  }
  if (!detail) {
    return (
      <Box p={4}>
        <Text>Loading…</Text>
      </Box>
    );
  }

  const cvss = band(detail.cvssV3Score);
  const patched = detail.contexts.filter((item) => item.status === "Patch available");
  const vendor = patched.length ? detail.severity : null;
  const sources = detail.sources;
  const cvssSource =
    sources?.cvss === "nvd" ? "NVD" : sources?.cvss === "advisory" ? sources.advisory || "advisory" : null;
  const epssSource = sources?.epss === "first" ? "FIRST" : sources?.epss === "nvd" ? "NVD" : null;
  const description = detail.description || "No description is stored for this CVE.";
  const descriptionLong = description.length > 180 || description.includes("\n");
  const statuses = [...new Set(detail.contexts.map((item) => fixStatusLabel(item.status)))];
  const statusLabel = statuses.length === 1 ? statuses[0] : "Mixed";
  const listed = detail.contexts.some((item) => item.status === "Patch available");
  const advisoryIds = [...new Set(detail.contexts.map((item) => item.advisory).filter(Boolean))] as string[];
  const metrics = parseCvss3Metrics(detail.cvssV3Vector);
  const vectorLabel = detail.cvssV3Vector?.includes("CVSS:3.0/")
    ? "CVSS v3.0 vector"
    : detail.cvssV3Vector?.includes("CVSS:3.1/")
      ? "CVSS v3.1 vector"
      : "CVSS v3 vector";
  const references = referenceItems(detail);

  return (
    <Box p={{ base: 4, md: 6 }} w="100%" minW={0}>
      <Flex wrap="wrap" align="flex-start" gap={6}>
        <Box flex="1 1 34rem" minW="18rem">
          <HStack spacing={2} fontSize="sm" color={muted}>
            <Link as={RouterLink} to="/cves" color={linkBlue}>
              CVEs
            </Link>
            <Text>/</Text>
            <Text>{detail.cve}</Text>
          </HStack>
          <HStack mt={3} spacing={3} align="center">
            <ErrataTitleShield />
            <Heading size="lg">{detail.cve}</Heading>
            <Badge colorScheme={severityScheme(vendor)} fontSize="0.8rem" px={2}>
              {vendor || "Unknown"}
            </Badge>
            <HStack spacing={1}>
              <Text fontSize="sm" color={muted}>
                (vendor severity)
              </Text>
              <MetricInfoHint id="vendor_severity" />
            </HStack>
          </HStack>
          <Text mt={3} noOfLines={showDescription ? undefined : 3} maxW="46rem">
            {description}
          </Text>
          {descriptionLong && (
            <Button
              mt={1}
              size="sm"
              variant="link"
              color={linkBlue}
              rightIcon={showDescription ? <ChevronUpIcon /> : <ChevronDownIcon />}
              onClick={() => setShowDescription((open) => !open)}
            >
              {showDescription ? "Hide full description" : "Show full description"}
            </Button>
          )}
          <Text mt={3} fontSize="sm" color={muted}>
            Published: {formatDay(detail.published)}
            <Text as="span" mx={3}>
              |
            </Text>
            Last modified: {formatDay(detail.updated)}
          </Text>
        </Box>
        <SimpleGrid columns={3} spacing={3} flex={{ base: "1 1 100%", lg: "0 0 28rem" }} w={{ base: "100%", lg: "28rem" }}>
          <MetricCard
            title="CVSS v3"
            helpId="cvss_v3"
            note={
              cvssSource
                ? `On this page the score is from ${cvssSource}. A dash means no CVSS v3 score is stored.`
                : undefined
            }
            bg={cardBg}
            borderColor={borderColor}
            muted={muted}
          >
            <HStack spacing={2} align="center">
              <Text fontSize="xl" fontWeight="700" lineHeight="1">
                {detail.cvssV3Score ? Number(detail.cvssV3Score).toFixed(1) : "—"}
              </Text>
              {cvss && (
                <Badge colorScheme={severityScheme(cvss)} fontSize="0.7rem">
                  {cvss}
                </Badge>
              )}
            </HStack>
            <Text fontSize="xs" color={muted}>
              ({cvssSource || "not recorded"})
            </Text>
          </MetricCard>
          <MetricCard
            title="EPSS"
            helpId="epss"
            note={epssNote(detail.epssPercentile, epssSource)}
            bg={cardBg}
            borderColor={borderColor}
            muted={muted}
          >
            <Text fontSize="xl" fontWeight="700" lineHeight="1">
              {detail.epssScore !== null ? `${(Number(detail.epssScore) * 100).toFixed(2)}%` : "—"}
            </Text>
            <Text fontSize="xs" color={muted}>
              ({epssSource || "not recorded"})
            </Text>
          </MetricCard>
          <MetricCard title="Rocky Linux status" helpId="rocky_status" bg={cardBg} borderColor={borderColor} muted={muted}>
            <Text fontWeight="700" fontSize="sm" color={listed && statuses.length === 1 ? COLOR_RESF_GREEN : muted}>
              {statusLabel}
            </Text>
            {statusLabel === "Not affected" && detail.contexts[0]?.reason ? (
              <Text fontSize="xs" color={muted}>
                {detail.contexts[0].reason}
              </Text>
            ) : advisoryIds.length === 1 ? (
              <Link as={RouterLink} to={`/${advisoryIds[0]}`} color={linkBlue} fontSize="xs">
                {advisoryIds[0]}
              </Link>
            ) : (
              <Text fontSize="xs" color={muted}>
                {advisoryIds.length ? `${advisoryIds.length} advisories` : "No advisory"}
              </Text>
            )}
          </MetricCard>
        </SimpleGrid>
      </Flex>

      <Box mt={6} borderWidth="1px" borderColor={borderColor} borderRadius="lg" bg={cardBg} p={{ base: 3, md: 4 }}>
        <HStack spacing={2}>
          <CubeIcon />
          <Heading size="md">Rocky Linux remediation</Heading>
        </HStack>
        <Text mt={1} mb={3} fontSize="sm" color={muted}>
          Affected Rocky Linux releases and the source package named by a Rocky advisory. A listed
          build is not an independently verified RPM.
        </Text>
        <Table size="sm" variant="simple" w="100%" sx={{ tableLayout: "fixed" }}>
          <Thead>
            <Tr>
              {["Release", "Source package", "Status", "Fixed source RPM EVR", "Advisory"].map((label) => (
                <Th
                  key={label}
                  textTransform="none"
                  letterSpacing="normal"
                  fontWeight="500"
                  fontSize="sm"
                  color={muted}
                  borderColor={borderColor}
                  w={label === "Fixed source RPM EVR" ? "28%" : undefined}
                >
                  {label === "Fixed source RPM EVR" ? (
                    <Tooltip label="Epoch, version, and release of the source RPM named by the advisory. A leading number and colon is the epoch. Epoch 0 is omitted in this column. The expanded row has the full source RPM filename to copy. This is not a binary RPM, and it is not a verified repository copy.">
                      Fixed source RPM EVR
                    </Tooltip>
                  ) : (
                    label
                  )}
                </Th>
              ))}
            </Tr>
          </Thead>
          <Tbody>
            {detail.contexts.map((item) => (
              <RemediationRow
                key={`${item.product}-${item.component}-${item.version}`}
                item={item}
                advisory={item.advisory ? advisories[item.advisory] : undefined}
                loaded={item.advisory ? item.advisory in advisories : true}
                muted={muted}
                linkBlue={linkBlue}
                borderColor={borderColor}
                insetBg={insetBg}
              />
            ))}
          </Tbody>
        </Table>
      </Box>

      <SimpleGrid mt={4} columns={{ base: 1, md: 2 }} spacing={4}>
        <Box borderWidth="1px" borderColor={borderColor} borderRadius="lg" bg={cardBg} p={4}>
          <HStack spacing={2} mb={3}>
            <ChartIcon />
            <Heading size="sm">Technical details</Heading>
          </HStack>
          <HStack justify="space-between" mb={1}>
            <Text fontSize="sm" color={muted}>
              {vectorLabel}
            </Text>
          </HStack>
          <HStack borderWidth="1px" borderColor={borderColor} borderRadius="md" px={2} py={1} bg={insetBg} align="center">
            <Text flex="1" fontFamily="mono" fontSize="xs" lineHeight="1.6">
              {detail.cvssV3Vector ? <SlashText value={detail.cvssV3Vector} /> : "No CVSS v3 vector is stored."}
            </Text>
            {detail.cvssV3Vector && <CopyIconButton value={detail.cvssV3Vector} label="Copy CVSS vector" />}
          </HStack>
          {Object.keys(metrics).length > 0 && (
            <Box
              mt={3}
              fontSize="sm"
              sx={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(14rem, 1fr))",
                columnGap: "2rem",
                rowGap: "0.125rem",
              }}
            >
              <MetricLine label="Attack Vector" value={metrics["Attack Vector"]} muted={muted} />
              <MetricLine label="Confidentiality" value={metrics["Confidentiality Impact"]} muted={muted} />
              <MetricLine label="Attack Complexity" value={metrics["Attack Complexity"]} muted={muted} />
              <MetricLine label="Integrity" value={metrics["Integrity Impact"]} muted={muted} />
              <MetricLine label="Privileges Required" value={metrics["Privileges Required"]} muted={muted} />
              <MetricLine label="Availability" value={metrics["Availability Impact"]} muted={muted} />
              <MetricLine label="Scope" value={metrics.Scope} muted={muted} />
            </Box>
          )}
          <SimpleGrid columns={{ base: 1, sm: 3 }} spacing={4} mt={4} pt={3} borderTopWidth="1px" borderColor={borderColor}>
            <Box>
              <HStack spacing={1} mb={1}>
                <Text fontSize="xs" color={muted}>
                  CWE
                </Text>
                <MetricInfoHint
                  id="cwe"
                  note={
                    sources?.cwe === "nvd"
                      ? "On this page the id is from NVD."
                      : sources?.cwe === "advisory"
                        ? "On this page the id is from the Rocky advisory. NVD did not record one."
                        : "No CWE is stored for this CVE."
                  }
                />
              </HStack>
              {cweIds(detail.cwe).length ? (
                <HStack spacing={3} flexWrap="wrap">
                  {cweIds(detail.cwe).map((id) => (
                    <Link
                      key={id}
                      href={`https://cwe.mitre.org/data/definitions/${id.replace(/\D/g, "")}.html`}
                      isExternal
                      color={linkBlue}
                      fontWeight="600"
                    >
                      {id} <ExternalLinkIcon mx="1px" />
                    </Link>
                  ))}
                </HStack>
              ) : (
                <Text fontWeight="600">{detail.cwe || "unavailable"}</Text>
              )}
            </Box>
            <Box>
              <HStack spacing={1} mb={1}>
                <Text fontSize="xs" color={muted}>
                  Exploit maturity
                </Text>
                <MetricInfoHint
                  id="exploit_maturity"
                  note={
                    sources?.exploitMaturity === "nvd"
                      ? "On this page the value is stored on the NVD record."
                      : sources?.exploitMaturity === "vector"
                        ? "On this page the value is derived from the stored CVSS vector. NVD did not store a separate exploit-maturity value."
                        : "Not recorded for this CVE."
                  }
                />
              </HStack>
              <Text fontWeight="600">
                {detail.exploitMaturity || "unavailable"}
                {sources?.exploitMaturity === "nvd" ? " (NVD)" : sources?.exploitMaturity === "vector" ? " (vector)" : ""}
              </Text>
            </Box>
            <Box>
              <HStack spacing={1} mb={1}>
                <Text fontSize="xs" color={muted}>
                  CISA KEV
                </Text>
                <MetricInfoHint id="kev" />
              </HStack>
              <Text fontWeight="600">{detail.kevListed ? "Listed" : "Not listed"}</Text>
            </Box>
          </SimpleGrid>
        </Box>

        <Box borderWidth="1px" borderColor={borderColor} borderRadius="lg" bg={cardBg} p={4}>
          <HStack spacing={2} mb={2}>
            <LinkIcon />
            <Heading size="sm">References</Heading>
          </HStack>
          <Stack spacing={0}>
            {references.map((item) => (
              <HStack key={item.href} borderTopWidth="1px" borderColor={borderColor} py={2} spacing={2}>
                {item.external ? (
                  <Link href={item.href} isExternal color={linkBlue} fontSize="sm" flex="1">
                    {item.label} <ExternalLinkIcon mx="2px" />
                  </Link>
                ) : (
                  <Link as={RouterLink} to={item.href} color={linkBlue} fontSize="sm" flex="1">
                    {item.label}
                  </Link>
                )}
              </HStack>
            ))}
          </Stack>
        </Box>
      </SimpleGrid>
    </Box>
  );
}

function referenceItems(detail: CveDetail): Array<{ href: string; label: string; external: boolean }> {
  const items: Array<{ href: string; label: string; external: boolean }> = [];
  const seen = new Set<string>();
  for (const name of advisoryNames(detail)) {
    items.push({ href: `/${name}`, label: `${name} — Rocky Linux security advisory`, external: false });
    seen.add(name);
  }
  const nvd = `https://nvd.nist.gov/vuln/detail/${detail.cve}`;
  items.push({ href: nvd, label: `NVD — ${detail.cve}`, external: true });
  seen.add(nvd);
  // An API document, not an SPA route: it must not go through the router.
  items.push({
    href: `/api/v3/csaf/vex/${encodeURIComponent(detail.cve)}`,
    label: "CSAF VEX",
    external: true,
  });
  for (const url of detail.references) {
    const href = safeHttpUrl(url);
    if (!href || seen.has(href)) continue;
    seen.add(href);
    items.push({ href, label: referenceLabel(href), external: true });
  }
  return items;
}

function SlashText({ value }: { value: string }) {
  const parts = value.split("/");
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={`${part}-${index}`}>
          {part}
          {index < parts.length - 1 && (
            <>
              /<wbr />
            </>
          )}
        </Fragment>
      ))}
    </>
  );
}

function SoftText({ value }: { value: string }) {
  const parts = value.split(/([+-])/);
  return (
    <Text>
      {parts.map((part, index) => (
        <Fragment key={`${part}-${index}`}>
          {part}
          {(part === "+" || part === "-") && <wbr />}
        </Fragment>
      ))}
    </Text>
  );
}

function epssNote(percentile: string | null, source: string | null): string {
  const origin = source
    ? `On this page the score is from ${source}.`
    : "Neither NVD nor FIRST.org has an EPSS score stored for this CVE.";
  const value = percentile != null && percentile !== "" ? Number(percentile) : null;
  if (value === null || !Number.isFinite(value)) return origin;
  const pct = value <= 1 ? value * 100 : value;
  return `${origin} Percentile ${pct.toFixed(0)} means this score is higher than about ${pct.toFixed(0)}% of scored CVEs.`;
}

function MetricCard({
  title,
  helpId,
  note,
  bg,
  borderColor,
  muted,
  children,
}: {
  title: string;
  helpId?: "cvss_v3" | "epss" | "rocky_status";
  note?: string;
  bg: string;
  borderColor: string;
  muted: string;
  children: ReactNode;
}) {
  return (
    <Box borderWidth="1px" borderColor={borderColor} borderRadius="lg" bg={bg} px={3} py={2} minH="5.5rem">
      <HStack spacing={1} mb={1} align="center">
        <Text fontSize="xs" color={muted}>
          {title}
        </Text>
        {helpId && <MetricInfoHint id={helpId} note={note} />}
      </HStack>
      {children}
    </Box>
  );
}

function MetricLine({ label, value, muted }: { label: string; value?: string; muted: string }) {
  return (
    <Flex justify="space-between" gap={3} py="1px" align="baseline">
      <Text color={muted}>{label}</Text>
      <Text textAlign="right">{value || "—"}</Text>
    </Flex>
  );
}

function RemediationRow({
  item,
  advisory,
  loaded,
  muted,
  linkBlue,
  borderColor,
  insetBg,
}: {
  item: CveContext;
  advisory: V2Advisory | undefined;
  loaded: boolean;
  muted: string;
  linkBlue: string;
  borderColor: string;
  insetBg: string;
}) {
  const [open, setOpen] = useState(false);
  const block = packagesFor(advisory, item.product);
  const sources = matchingSources(block?.nvras ?? [], item.component);
  const binaries = (block?.nvras ?? [])
    .filter((nevra) => !isSource(nevra))
    .map(parseRpm)
    .filter((rpm): rpm is ParsedRpm => rpm !== null);
  const assigned = assignBinaries(sources, binaries);
  const evrs = sources.map(displayEvr);
  const shown =
    evrs.length > 0 ? evrs : item.status === "Patch available" && item.version ? [item.version] : [];
  const patched = item.status === "Patch available";

  return (
    <Fragment>
      <Tr>
        <Td borderColor={borderColor}>{item.product}</Td>
        <Td borderColor={borderColor}>
          {item.status === "Not affected" ? "—" : item.component || "Unknown"}
        </Td>
        <Td borderColor={borderColor} color={patched ? COLOR_RESF_GREEN : muted}>
          {fixStatusLabel(item.status)}
          {item.status === "Not affected" && item.justification ? (
            <Text fontSize="xs" color={muted}>
              {item.justification}
            </Text>
          ) : null}
        </Td>
        <Td borderColor={borderColor} fontFamily="mono" fontSize="xs">
          {item.status === "Not affected"
            ? "—"
            : shown.length
              ? shown.map((value) => <SoftText key={value} value={value} />)
              : "Unknown"}
        </Td>
        <Td borderColor={borderColor}>
          <Flex align="center" justify="space-between" gap={2}>
            {item.advisory ? (
              <Link as={RouterLink} to={`/${item.advisory}`} color={linkBlue} fontSize="sm">
                {item.advisory}
              </Link>
            ) : (
              <Text color={muted}>None</Text>
            )}
            <IconButton
              flexShrink={0}
              aria-label={open ? "Hide package details" : "Show package details"}
              aria-expanded={open}
              icon={open ? <ChevronUpIcon /> : <ChevronDownIcon />}
              size="xs"
              variant="ghost"
              onClick={() => setOpen((value) => !value)}
            />
          </Flex>
        </Td>
      </Tr>
      {open && (
        <Tr>
          <Td colSpan={5} borderColor={borderColor} bg={insetBg} p={3}>
            <PackageDetails
              item={item}
              advisory={advisory}
              loaded={loaded}
              assigned={assigned}
              repos={block?.repositories ?? []}
              muted={muted}
              borderColor={borderColor}
            />
          </Td>
        </Tr>
      )}
    </Fragment>
  );
}

function PackageDetails({
  item,
  advisory,
  loaded,
  assigned,
  repos,
  muted,
  borderColor,
}: {
  item: CveContext;
  advisory: V2Advisory | undefined;
  loaded: boolean;
  assigned: ReturnType<typeof assignBinaries>;
  repos: string[];
  muted: string;
  borderColor: string;
}) {
  if (item.advisory && !loaded) return <Text fontSize="sm">Looking up the advisory…</Text>;
  const sourceRpms = assigned.groups.map((group) => group.source);
  const relatedUnmatched = assigned.unmatched.filter((rpm) => sourceRpms.some((source) => sameEvr(source, rpm)));
  const chipBorder = borderColor;
  return (
    <Box borderWidth="1px" borderColor={borderColor} borderRadius="md" p={4}>
      {assigned.groups.length === 0 && (
        <Text fontSize="sm" mb={3}>
          No source RPM is recorded for this release.
        </Text>
      )}
      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
        <Box>
          <Text fontWeight="600" mb={3}>
            Package details
          </Text>
          <Grid templateColumns="8.5rem 1fr" gap={2} alignItems="start" fontSize="sm">
            <Text color={muted}>Source RPMs</Text>
            <HStack spacing={2} flexWrap="wrap">
              {assigned.groups.length ? (
                assigned.groups.map((group) => (
                  <Tooltip key={group.source.nevra} label={group.source.nevra}>
                    <Box
                      px={2}
                      py={0.5}
                      borderWidth="1px"
                      borderColor={chipBorder}
                      borderRadius="md"
                      fontFamily="mono"
                      fontSize="xs"
                    >
                      {assigned.groups.length > 1
                        ? `${group.source.name}-${displayEvr(group.source)}.src.rpm`
                        : `${group.source.name}.src.rpm`}
                    </Box>
                  </Tooltip>
                ))
              ) : (
                <Text>Unknown</Text>
              )}
            </HStack>
            <Text color={muted}>Repository</Text>
            <Text>
              {item.advisory ? repos.join(", ") || "not recorded on the advisory" : "unknown"}
              {item.advisory && (
                <Text as="span" color={muted}>
                  {" "}
                  — named on the advisory, not a check that the RPM is there now
                </Text>
              )}
            </Text>
            <Text color={muted}>Advisory date</Text>
            <Text>{formatDay(advisory?.publishedAt || item.advisories[0]?.published)}</Text>
            <Text color={muted}>Rocky published</Text>
            <Text>{formatDay(advisory?.rockyPublishedAt)}</Text>
            <Text color={muted}>Verified RPM availability</Text>
            <Text>not performed</Text>
            <Text color={muted}>Evidence</Text>
            <Text>
              {item.advisory
                ? `Rocky Linux advisory ${item.advisory} identifies this source package and fixed build. Independent repository availability verification has not been performed.`
                : "No Rocky advisory names a fixed source package for this release."}
            </Text>
          </Grid>
        </Box>
        <Stack spacing={4}>
          {assigned.groups.map((group) => (
            <BinaryGroup
              key={group.source.nevra}
              title={
                assigned.groups.length > 1
                  ? `Binary RPMs for ${group.source.name}`
                  : "Binary RPMs"
              }
              binaries={group.binaries}
              muted={muted}
            />
          ))}
          {relatedUnmatched.length > 0 && (
            <BinaryGroup title="Binary RPMs not matched to one source RPM" binaries={relatedUnmatched} muted={muted} />
          )}
        </Stack>
      </SimpleGrid>
    </Box>
  );
}

function BinaryGroup({ title, binaries, muted }: { title: string; binaries: ParsedRpm[]; muted: string }) {
  const installable = binaries.filter((rpm) => !isDebug(rpm.nevra));
  const debug = binaries.filter((rpm) => isDebug(rpm.nevra));
  const payload = installable.map((rpm) => rpm.nevra).join("\n");
  return (
    <Box>
      <Flex justify="space-between" align="center" mb={1}>
        <Text fontWeight="600">
          {title} ({installable.length})
        </Text>
        <CopyTextButton value={payload} disabled={!payload} />
      </Flex>
      {byArch(installable).map(([arch, rpms]) => (
        <ArchRow key={arch} label={arch} rpms={rpms} muted={muted} />
      ))}
      {debug.length > 0 && <ArchRow label="debuginfo" rpms={debug} muted={muted} />}
      {installable.length === 0 && debug.length === 0 && (
        <Text fontSize="sm" color={muted}>
          No binary RPM is recorded.
        </Text>
      )}
    </Box>
  );
}

function ArchRow({ label, rpms, muted }: { label: string; rpms: ParsedRpm[]; muted: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Box>
      <Button
        variant="ghost"
        size="sm"
        h={7}
        px={1}
        fontWeight="400"
        leftIcon={open ? <ChevronDownIcon /> : <ChevronRightIcon />}
        onClick={() => setOpen((value) => !value)}
      >
        {label} ({rpms.length})
      </Button>
      <Collapse in={open}>
        <Stack pl={6} spacing={0} pb={1}>
          {rpms.map((rpm) => (
            <Text key={rpm.nevra} fontFamily="mono" fontSize="xs" color={muted} wordBreak="break-all">
              {rpm.nevra}
            </Text>
          ))}
        </Stack>
      </Collapse>
    </Box>
  );
}

function CopyTextButton({ value, disabled }: { value: string; disabled?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="xs"
      variant="outline"
      leftIcon={<CopyIcon />}
      isDisabled={disabled}
      onClick={() => {
        copyText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {copied ? "Copied" : "Copy NEVRA"}
    </Button>
  );
}

function CopyIconButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <IconButton
      aria-label={copied ? "Copied" : label}
      icon={copied ? <CheckIcon /> : <CopyIcon />}
      size="xs"
      variant="ghost"
      onClick={() => {
        copyText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        });
      }}
    />
  );
}

function CubeIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" boxSize="5" color={COLOR_RESF_GREEN} aria-hidden>
      <path
        fill="currentColor"
        d="M12 2 3 7v10l9 5 9-5V7l-9-5zm0 2.2 6.4 3.5L12 11.2 5.6 7.7 12 4.2zM5 9.4l6 3.3v6.8l-6-3.3V9.4zm14 0v6.8l-6 3.3v-6.8l6-3.3z"
      />
    </Box>
  );
}

function ChartIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" boxSize="5" color={COLOR_RESF_GREEN} aria-hidden>
      <path fill="currentColor" d="M4 20h2V10H4v10zm7 0h2V4h-2v16zm7 0h2v-7h-2v7z" />
    </Box>
  );
}

function LinkIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" boxSize="5" color={COLOR_RESF_GREEN} aria-hidden>
      <path
        fill="currentColor"
        d="M10.6 13.4a1 1 0 0 1 0-1.4l2.8-2.8a3 3 0 0 1 4.2 4.2l-1.4 1.4a1 1 0 1 1-1.4-1.4l1.4-1.4a1 1 0 0 0-1.4-1.4l-2.8 2.8a1 1 0 0 1-1.4 0zm2.8-2.8a1 1 0 0 1 0 1.4l-2.8 2.8a1 1 0 0 0 1.4 1.4l2.8-2.8a3 3 0 1 0-4.2-4.2l-1.4 1.4a1 1 0 1 0 1.4 1.4l1.4-1.4a1 1 0 0 1 1.4 0z"
      />
    </Box>
  );
}
