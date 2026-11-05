import {
  CheckCircleIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  DownloadIcon,
  ExternalLinkIcon,
  InfoOutlineIcon,
  TriangleDownIcon,
  TriangleUpIcon,
} from "@chakra-ui/icons";
import {
  Badge,
  Box,
  Button,
  Collapse,
  Flex,
  FormControl,
  FormLabel,
  Heading,
  HStack,
  IconButton,
  Input,
  Link,
  Menu,
  MenuButton,
  MenuItem,
  MenuList,
  Select,
  Spinner,
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
import { Link as RouterLink } from "react-router-dom";

import {
  exportUrl,
  listTrackerCveGroups,
  listTrackerCves,
  listTrackerProducts,
  type CveGroup,
  type CveRow,
} from "../../api/tracker";
import { cvssScoreToSeverity, parseScore } from "../../lib/nvd";
import { COLOR_RESF_GREEN } from "../../styles";
import { fixStatusLabel, severityColor } from "./Filters";
import { useDebouncedQuery, useTrackerParams } from "./params";

const GROUP_SORTS = new Set(["cve", "severity", "cvss", "status", "published", "product"]);
const RECORD_SORTS = new Set(["cve", "severity", "component", "product", "status", "published"]);

function formatDate(value: string | null): string {
  if (!value) return "—";
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
  if (!match) return value;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function vendorSeverity(row: CveRow): string {
  return row.status === "Patch available" ? row.severity : "—";
}

function cvssSeverity(row: CveRow): string {
  const band = cvssScoreToSeverity(parseScore(row.cvssV3Score));
  if (band !== "NONE") return band[0] + band.slice(1).toLowerCase();
  if (row.status !== "Patch available" && row.severity !== "Awaiting analysis") {
    return row.severity;
  }
  return "—";
}

function releaseMajor(name: string): number | null {
  const match = /^Rocky Linux\s+(\d+)/.exec(name);
  return match ? Number(match[1]) : null;
}

function releaseSummary(releases: string[]): string {
  if (!releases.length) return "—";
  const ordered = [...releases].sort((a, b) => {
    const left = releaseMajor(a);
    const right = releaseMajor(b);
    if (left != null && right != null && left !== right) return left - right;
    return a.localeCompare(b);
  });
  if (ordered.every((name) => releaseMajor(name) != null)) {
    return `Rocky ${ordered.map((name) => releaseMajor(name)).join(", ")}`;
  }
  return ordered.join(", ");
}

function fixedEvr(row: CveRow): string {
  if (row.status !== "Patch available" || !row.version) return "—";
  if (row.epoch && row.epoch !== "0") return `${row.epoch}:${row.version}`;
  return row.version;
}

function recordEvidence(row: CveRow): { text: string; title: string } {
  if (row.status === "Not affected") {
    const justification = row.justification || "component_not_present";
    return {
      text: row.reason || "Rocky Linux does not ship this component.",
      title: `Justification: ${justification}. The component is absent from Rocky repository metadata, and no Rocky or Red Hat advisory lists this CVE.`,
    };
  }
  if (row.advisory) {
    return {
      text: "Advisory identifies this package and fixed build.",
      title: `Rocky Linux advisory ${row.advisory} identifies this source package and fixed build. Independent repository availability verification has not been performed.`,
    };
  }
  const text = "No Rocky advisory names a fixed source package for this release.";
  return { text, title: row.reason ? `${row.reason}. ${text}` : text };
}

function Hint({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <Tooltip
      label={label}
      hasArrow
      placement="top"
      openDelay={300}
      bg="gray.800"
      color="white"
      maxW="16rem"
      fontSize="xs"
      fontWeight="normal"
      lineHeight="1.4"
      px={2}
      py={1.5}
      borderRadius="md"
      textAlign="left"
    >
      {children}
    </Tooltip>
  );
}

const VENDOR_SEVERITY_HINT = "Severity assigned by the Rocky Linux advisory; may differ from CVSS.";

function aggregateLook(status: string): { label: string; tone: "fixed" | "mixed" | "open"; detail: string } {
  if (status === "Fix listed for all matching records") {
    return {
      label: "Fix listed",
      tone: "fixed",
      detail:
        "All matching records have a fixed build listed in a Rocky Linux advisory. Repository availability has not been independently verified.",
    };
  }
  if (status === "Mixed status") {
    return {
      label: "Mixed",
      tone: "mixed",
      detail: "The matching records do not all have the same fix status. Expand the row to see each one.",
    };
  }
  if (status === "Under investigation") {
    return {
      label: "Under investigation",
      tone: "open",
      detail: "Every matching record is still open.",
    };
  }
  if (status === "Not affected") {
    return {
      label: "Not affected",
      tone: "open",
      detail:
        "Rocky repository metadata does not contain the vulnerable component, and no Rocky or Red Hat advisory lists this CVE.",
    };
  }
  return {
    label: status,
    tone: "open",
    detail:
      "No Rocky build matched the linked upstream advisory. This does not mean the package is unaffected.",
  };
}

export function TrackerPager({
  page,
  limit,
  total,
  noun = "results",
}: {
  page: number;
  limit: number;
  total: number;
  noun?: string;
}) {
  const { update } = useTrackerParams();
  const pages = Math.max(1, Math.ceil(total / limit));
  const shown = total === 1 && noun === "CVEs" ? "CVE" : total === 1 && noun === "records" ? "record" : noun;
  return (
    <HStack justify="space-between" mt={4}>
      <Text fontSize="sm">
        {total.toLocaleString()} {shown}, page {page.toLocaleString()} of {pages.toLocaleString()}
      </Text>
      <HStack>
        <Button
          size="sm"
          isDisabled={page <= 1}
          onClick={() => update({ page: String(page - 1) }, false)}
        >
          Previous
        </Button>
        <Button
          size="sm"
          isDisabled={page >= pages}
          onClick={() => update({ page: String(page + 1) }, false)}
        >
          Next
        </Button>
      </HStack>
    </HStack>
  );
}

function SortHeader({
  label,
  column,
  tooltip,
}: {
  label: string;
  column: string;
  tooltip?: string;
}) {
  const { params, update } = useTrackerParams();
  const active = (params.get("sort_column") || "published") === column;
  const order = params.get("sort_order") || "desc";
  const mute = useColorModeValue("gray.400", "gray.500");
  const mark = useColorModeValue("gray.800", "white");
  const next = active && order === "desc" ? "asc" : "desc";
  const button = (
    <Button
      variant="ghost"
      size="xs"
      px={1}
      aria-label={`Sort by ${label}`}
      onClick={() =>
        update({
          sort_column: column,
          sort_order: next,
        })
      }
    >
      {label}
      <Box display="inline-flex" flexDirection="column" ml={1} lineHeight="0">
        <TriangleUpIcon boxSize="2" color={active && order === "asc" ? mark : mute} />
        <TriangleDownIcon boxSize="2" mt="1px" color={active && order === "desc" ? mark : mute} />
      </Box>
    </Button>
  );
  return (
    <Th aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      {tooltip ? <Hint label={tooltip}>{button}</Hint> : button}
    </Th>
  );
}

function RecordRows({ rows }: { rows: CveRow[] }) {
  return (
    <>
      {rows.map((row) => {
        const query = new URLSearchParams();
        if (row.product) query.set("product", row.product);
        if (row.component) query.set("component", row.component);
        if (row.version) query.set("version", row.version);
        return (
          <Tr key={`${row.cve}-${row.product}-${row.component}-${row.version}`}>
            <Td fontFamily="mono">
              <Link
                as={RouterLink}
                to={`/cves/${encodeURIComponent(row.cve)}?${query.toString()}`}
                color="blue.500"
              >
                {row.cve}
              </Link>
            </Td>
            <Td>
              <Text color={`${severityColor(vendorSeverity(row))}.500`}>{vendorSeverity(row)}</Text>
            </Td>
            <Td>
              <Text color={`${severityColor(cvssSeverity(row))}.500`}>
                {cvssSeverity(row)}
                {row.cvssV3Score ? ` ${Number(row.cvssV3Score).toFixed(1)}` : ""}
              </Text>
            </Td>
            <Td>{row.component || "—"}</Td>
            <Td>{row.product}</Td>
            <Td>{fixStatusLabel(row.status)}</Td>
            <Td fontFamily="mono">{fixedEvr(row)}</Td>
            <Td>
              <Hint label="NVD publication date. A Rocky or Red Hat advisory date is not shown here.">
                {formatDate(row.published)}
              </Hint>
            </Td>
          </Tr>
        );
      })}
      {!rows.length && (
        <Tr>
          <Td colSpan={8}>No CVEs match these filters.</Td>
        </Tr>
      )}
    </>
  );
}

function ScoreCell({ score, band }: { score: string | null | undefined; band: string }) {
  if (!score || band === "—") return <Text>—</Text>;
  return (
    <HStack spacing={2}>
      <Text fontWeight="700">{Number(score).toFixed(1)}</Text>
      <Badge colorScheme={severityColor(band)} variant="subtle">
        {band}
      </Badge>
    </HStack>
  );
}

function RemediationStatus({
  status,
  expanded,
  onToggle,
}: {
  status: string;
  expanded: boolean;
  onToggle: () => void;
}) {
  const look = aggregateLook(status);
  const color = look.tone === "fixed" ? COLOR_RESF_GREEN : look.tone === "mixed" ? "orange.300" : "gray.400";
  const hover = useColorModeValue("blackAlpha.50", "whiteAlpha.100");
  return (
    <Hint label={look.detail}>
      <Button
        type="button"
        variant="ghost"
        size="xs"
        h="auto"
        minW={0}
        px={1}
        py={0.5}
        color={color}
        fontWeight="600"
        aria-expanded={expanded}
        aria-label={`${look.label}. ${look.detail}`}
        _hover={{ bg: hover }}
        onClick={onToggle}
      >
        <HStack spacing={1.5} whiteSpace="nowrap">
          {look.tone === "fixed" ? (
            <CheckCircleIcon boxSize="3.5" />
          ) : (
            <Box boxSize="9px" borderRadius="full" borderWidth="2px" borderColor={color} flexShrink={0} />
          )}
          <Text fontWeight="600" fontSize="sm">
            {look.label}
          </Text>
        </HStack>
      </Button>
    </Hint>
  );
}

function GroupRows({ rows }: { rows: CveGroup[] }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const muted = useColorModeValue("gray.600", "gray.400");
  const summaryColor = useColorModeValue("gray.700", "gray.300");
  const inset = useColorModeValue("gray.50", "blackAlpha.400");
  const panelBorder = useColorModeValue("gray.200", "whiteAlpha.200");
  const linkBlue = useColorModeValue("blue.600", "blue.300");

  useEffect(() => {
    setOpen({});
  }, [rows]);

  function toggle(cve: string) {
    setOpen((current) => ({ ...current, [cve]: !current[cve] }));
  }

  return (
    <>
      {rows.map((row) => {
        const expanded = Boolean(open[row.cve]);
        const vendor = row.vendorSeverity || "—";
        const cvss = row.cvssSeverity || "—";
        return (
          <Fragment key={row.cve}>
            <Tr>
              <Td w="36px" px={1}>
                <IconButton
                  aria-label={`${expanded ? "Hide" : "Show"} remediation for ${row.cve}`}
                  aria-expanded={expanded}
                  icon={expanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
                  size="xs"
                  variant="ghost"
                  onClick={() => toggle(row.cve)}
                />
              </Td>
              <Td whiteSpace="nowrap">
                <Link as={RouterLink} to={`/cves/${encodeURIComponent(row.cve)}`} color={linkBlue} fontFamily="mono" fontWeight="600">
                  {row.cve}
                </Link>
              </Td>
              <Td maxW="22rem">
                <Text fontSize="sm" color={summaryColor} noOfLines={2} minH="2.5rem" lineHeight="1.25rem">
                  {row.description || "—"}
                </Text>
              </Td>
              <Td>
                <Hint
                  label={
                    row.vendorSeverityMixed
                      ? `${VENDOR_SEVERITY_HINT} Matching advisories do not all assign this severity.`
                      : VENDOR_SEVERITY_HINT
                  }
                >
                  <Text tabIndex={0} fontWeight="700" color={vendor === "—" ? muted : `${severityColor(vendor)}.400`}>
                    {vendor}
                  </Text>
                </Hint>
              </Td>
              <Td>
                <ScoreCell score={row.cvssV3Score} band={cvss} />
              </Td>
              <Td whiteSpace="nowrap">
                <Hint label={row.releases.join(", ") || "No release is recorded"}>
                  {releaseSummary(row.releases)}
                </Hint>
              </Td>
              <Td>
                <RemediationStatus status={row.status} expanded={expanded} onToggle={() => toggle(row.cve)} />
              </Td>
              <Td whiteSpace="nowrap">
                <Hint label="NVD publication date. A Rocky or Red Hat advisory date is not shown here.">
                  {formatDate(row.published)}
                </Hint>
              </Td>
            </Tr>
            {expanded && (
              <Tr>
                <Td colSpan={8} bg={inset} p={3}>
                  <Box borderWidth="1px" borderColor={panelBorder} borderRadius="md" p={3}>
                    <HStack spacing={2} mb={2}>
                      <CubeIcon />
                      <Text fontWeight="700">
                        Affected packages and fixes ({row.records.length}{" "}
                        {row.records.length === 1 ? "record" : "records"})
                      </Text>
                    </HStack>
                    <Table size="sm" variant="simple">
                      <Thead>
                        <Tr>
                          <Th>Release</Th>
                          <Th>Source package</Th>
                          <Th>Fix status</Th>
                          <Th>Fixed source RPM EVR</Th>
                          <Th>Advisory</Th>
                          <Th>Evidence / provenance</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {[...row.records]
                          .sort(
                            (left, right) =>
                              (releaseMajor(left.product) ?? 999) - (releaseMajor(right.product) ?? 999) ||
                              (left.component || "").localeCompare(right.component || "")
                          )
                          .map((record) => {
                          const evidence = recordEvidence(record);
                          const listed = record.status === "Patch available";
                          return (
                            <Tr key={`${record.product}-${record.component}-${record.version}-${record.advisory}`}>
                              <Td whiteSpace="nowrap">{record.product}</Td>
                              <Td>{record.component || "—"}</Td>
                              <Td whiteSpace="nowrap" color={listed ? COLOR_RESF_GREEN : muted} fontWeight={listed ? "600" : undefined}>
                                {listed && <CheckCircleIcon boxSize="3" mr={1} />}
                                {fixStatusLabel(record.status)}
                              </Td>
                              <Td fontFamily="mono" fontSize="xs">
                                {fixedEvr(record)}
                              </Td>
                              <Td whiteSpace="nowrap">
                                {record.advisory ? (
                                  <Link as={RouterLink} to={`/${record.advisory}`} color={linkBlue}>
                                    {record.advisory} <ExternalLinkIcon mx="2px" />
                                  </Link>
                                ) : (
                                  "—"
                                )}
                              </Td>
                              <Td fontSize="xs" color={muted} maxW="16rem">
                                <Hint label={evidence.title}>{evidence.text}</Hint>
                              </Td>
                            </Tr>
                          );
                        })}
                      </Tbody>
                    </Table>
                    <HStack mt={3} spacing={2} color={muted} fontSize="xs">
                      <InfoOutlineIcon />
                      <Text>
                        Package associations are advisory-derived; they do not independently establish component
                        vulnerability.
                      </Text>
                    </HStack>
                  </Box>
                </Td>
              </Tr>
            )}
          </Fragment>
        );
      })}
      {!rows.length && (
        <Tr>
          <Td colSpan={8}>No CVEs match these filters.</Td>
        </Tr>
      )}
    </>
  );
}

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Awaiting analysis"];
const STATUS_OPTIONS = [
  { value: "Patch available", label: "Fix listed in advisory" },
  { value: "In research", label: "In research" },
  { value: "Not shipped", label: "Not shipped" },
  { value: "Not affected", label: "Not affected" },
];

function FilterIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" boxSize="4" aria-hidden>
      <path fill="currentColor" d="M3 5h18l-7 8v5l-4 2v-7L3 5z" />
    </Box>
  );
}

function CubeIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" boxSize="4" color={COLOR_RESF_GREEN} aria-hidden>
      <path
        fill="currentColor"
        d="M12 2 3 7v10l9 5 9-5V7l-9-5zm0 2.2 6.4 3.5L12 11.2 5.6 7.7 12 4.2zM5 9.4l6 3.3v6.8l-6-3.3V9.4zm14 0v6.8l-6 3.3v-6.8l6-3.3z"
      />
    </Box>
  );
}

function pageWindow(current: number, total: number): Array<number | "gap"> {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const pages = new Set<number>([1, total, current, current - 1, current + 1]);
  if (current <= 4) {
    for (let page = 2; page <= 4; page += 1) pages.add(page);
  }
  if (current >= total - 3) {
    for (let page = total - 3; page < total; page += 1) pages.add(page);
  }
  const sorted = [...pages].filter((page) => page >= 1 && page <= total).sort((a, b) => a - b);
  const items: Array<number | "gap"> = [];
  sorted.forEach((page, index) => {
    if (index > 0 && page - sorted[index - 1] > 1) items.push("gap");
    items.push(page);
  });
  return items;
}

function ExplorerPager({
  page,
  limit,
  total,
  noun,
}: {
  page: number;
  limit: number;
  total: number;
  noun: string;
}) {
  const { update } = useTrackerParams();
  const pages = Math.max(1, Math.ceil(total / Math.max(limit, 1)));
  const start = total === 0 ? 0 : (page - 1) * limit + 1;
  const end = Math.min(page * limit, total);
  const sizes = [25, 50, 100].includes(limit) ? [25, 50, 100] : [limit, 25, 50, 100];
  return (
    <HStack justify="space-between" mt={4} flexWrap="wrap" spacing={3}>
      <Text fontSize="sm">
        Showing {start.toLocaleString()} – {end.toLocaleString()} of {total.toLocaleString()} {noun}
      </Text>
      <HStack>
        <IconButton
          aria-label="Previous page"
          icon={<ChevronLeftIcon />}
          size="sm"
          variant="outline"
          isDisabled={page <= 1}
          onClick={() => update({ page: String(page - 1) }, false)}
        />
        {pageWindow(page, pages).map((item, index) =>
          item === "gap" ? (
            <Text key={`gap-${index}`} px={1} color="gray.500">
              …
            </Text>
          ) : (
            <Button
              key={item}
              size="sm"
              minW="8"
              variant={item === page ? "solid" : "outline"}
              bg={item === page ? COLOR_RESF_GREEN : undefined}
              color={item === page ? "white" : undefined}
              _hover={item === page ? { bg: COLOR_RESF_GREEN } : undefined}
              onClick={() => update({ page: String(item) }, false)}
            >
              {item}
            </Button>
          )
        )}
        <IconButton
          aria-label="Next page"
          icon={<ChevronRightIcon />}
          size="sm"
          variant="outline"
          isDisabled={page >= pages}
          onClick={() => update({ page: String(page + 1) }, false)}
        />
        <Select
          aria-label="Rows per page"
          size="sm"
          w="20"
          value={String(limit)}
          onChange={(event) => update({ limit: event.target.value })}
        >
          {sizes.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </Select>
      </HStack>
    </HStack>
  );
}

export function CveList() {
  const { params, update, page } = useTrackerParams();
  const limit = Math.min(100, Math.max(1, Number(params.get("limit") || "25") || 25));
  const grouped = params.get("view") !== "records";
  const [rows, setRows] = useState<CveRow[]>([]);
  const [groups, setGroups] = useState<CveGroup[]>([]);
  const [total, setTotal] = useState(0);
  const [products, setProducts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const tableBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "whiteAlpha.200");
  const muted = useColorModeValue("gray.600", "gray.400");
  const countColor = useColorModeValue("gray.800", "white");
  const inputBackground = useColorModeValue("white", "gray.700");
  const { draft, setDraft } = useDebouncedQuery(params, update);
  const selectedProducts = params.getAll("product");
  const selectedSeverities = params.getAll("severity");
  const datesActive = Boolean(params.get("date_after") || params.get("date_before"));
  const [advancedOpen, setAdvancedOpen] = useState(datesActive);
  const exportParams = new URLSearchParams(params);
  exportParams.set("view", grouped ? "cves" : "records");

  useEffect(() => {
    if (datesActive) setAdvancedOpen(true);
  }, [datesActive]);

  useEffect(() => {
    if (grouped && params.get("sort_column") === "component") {
      update({ sort_column: null, sort_order: null });
    }
  }, [grouped, params, update]);

  useEffect(() => {
    document.title = "CVE Explorer";
    listTrackerProducts()
      .then((result) => setProducts(result.data.map((item) => item.name)))
      .catch(() => setProducts([]));
  }, []);

  useEffect(() => {
    const query = new URLSearchParams(params);
    query.set("page", String(page));
    query.set("limit", String(limit));
    query.set("view", grouped ? "cves" : "records");
    if (grouped && query.get("sort_column") === "component") {
      query.delete("sort_column");
      query.delete("sort_order");
    }
    let cancelled = false;
    setLoading(true);
    const request = grouped ? listTrackerCveGroups(query) : listTrackerCves(query);
    request
      .then((result) => {
        if (cancelled) return;
        if (grouped) {
          setGroups(result.data as CveGroup[]);
          setRows([]);
        } else {
          setRows(result.data as CveRow[]);
          setGroups([]);
        }
        setTotal(result.meta.total);
        setError(false);
      })
      .catch(() => {
        if (!cancelled) setError(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [params, page, limit, grouped]);

  function setView(next: "cves" | "records") {
    const sort = params.get("sort_column");
    const allowed = next === "cves" ? GROUP_SORTS : RECORD_SORTS;
    const keepSort = sort && allowed.has(sort);
    update({
      view: next === "records" ? "records" : null,
      sort_column: keepSort ? sort : null,
      sort_order: keepSort ? params.get("sort_order") : null,
    });
  }

  const productValue = selectedProducts.length === 1 ? selectedProducts[0] : "";
  const severityValue = selectedSeverities.length === 1 ? selectedSeverities[0] : "";

  return (
    <Box p={4}>
      <HStack justify="space-between" align="flex-start" spacing={4}>
        <Box flex="1" minW="0">
          <Heading size="lg">CVE Explorer</Heading>
          <Text mt={1} fontSize="sm" color={muted}>
            Browse security vulnerabilities affecting Rocky Linux, with remediation status, affected packages,
            and advisory information.
          </Text>
        </Box>
        <HStack spacing={2} flexShrink={0} pt={1}>
          <Text fontSize="sm" color={muted}>
            View:
          </Text>
          <Button
            size="sm"
            variant="outline"
            aria-pressed={grouped}
            borderColor={grouped ? COLOR_RESF_GREEN : undefined}
            color={grouped ? COLOR_RESF_GREEN : undefined}
            onClick={() => setView("cves")}
          >
            CVEs (grouped)
          </Button>
          <Button
            size="sm"
            variant="outline"
            aria-pressed={!grouped}
            borderColor={!grouped ? COLOR_RESF_GREEN : undefined}
            color={!grouped ? COLOR_RESF_GREEN : undefined}
            onClick={() => setView("records")}
          >
            Detailed records
          </Button>
          <Hint
            label={
              grouped
                ? "One row per CVE. Select Fix listed, or the expand control, to show the matching package and advisory records. Fix listed means all matching records have a fixed build listed in a Rocky Linux advisory. Repository availability has not been independently verified. Mixed means the records do not all agree. Under investigation is still open. No matching Rocky build is not a not-affected result."
                : "One row per CVE, source package, and Rocky Linux release. Fix listed in advisory names a fixed build. Repository availability has not been independently verified. Not shipped does not mean the package is unaffected. Not affected is recorded only when repository metadata shows the component is absent."
            }
          >
            <InfoOutlineIcon tabIndex={0} color={muted} aria-label="About this view" />
          </Hint>
        </HStack>
      </HStack>
      <Flex mt={4} gap={3} direction={{ base: "column", lg: "row" }} align={{ lg: "flex-end" }}>
        <FormControl flex={{ lg: "1 1 50%" }} maxW={{ lg: "50%" }} w={{ base: "100%", lg: "auto" }}>
          <FormLabel fontSize="xs" mb={1}>
            Search
          </FormLabel>
          <Input
            aria-label="Search"
            placeholder="Search CVE, package, or CVSS vector (e.g. CVE-2026-106074, nodejs, AV:N)"
            value={draft}
            background={inputBackground}
            onChange={(event) => setDraft(event.target.value)}
          />
        </FormControl>
        <Flex flex="1" gap={3} w={{ base: "100%", lg: "auto" }} wrap="wrap" align="flex-end">
        <FormControl flex="1 1 11.5rem" minW="11.5rem">
          <FormLabel fontSize="xs" mb={1}>
            Product
          </FormLabel>
          <Select
            aria-label="Product"
            background={inputBackground}
            value={productValue}
            onChange={(event) => update({ product: event.target.value ? [event.target.value] : [] })}
          >
            <option value="">All Rocky Linux</option>
            {products.map((product) => (
              <option key={product} value={product}>
                {product}
              </option>
            ))}
          </Select>
        </FormControl>
        <FormControl flex="1 1 9rem" minW="9rem">
          <FormLabel fontSize="xs" mb={1}>
            Status
          </FormLabel>
          <Select
            aria-label="Status"
            background={inputBackground}
            value={params.get("status") ?? ""}
            onChange={(event) => update({ status: event.target.value || null })}
          >
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status.value} value={status.value}>
                {status.label}
              </option>
            ))}
          </Select>
        </FormControl>
        <FormControl flex="1 1 9rem" minW="9rem">
          <FormLabel fontSize="xs" mb={1}>
            Severity
          </FormLabel>
          <Select
            aria-label="Severity"
            background={inputBackground}
            value={severityValue}
            onChange={(event) => update({ severity: event.target.value ? [event.target.value] : [] })}
          >
            <option value="">All severities</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </Select>
        </FormControl>
        </Flex>
      </Flex>
      <HStack mt={3} justify="space-between" flexWrap="wrap" spacing={3}>
        <Button
          size="sm"
          variant="outline"
          leftIcon={<FilterIcon />}
          aria-expanded={advancedOpen}
          onClick={() => setAdvancedOpen((open) => !open)}
        >
          Advanced filters
        </Button>
        <HStack spacing={3} fontSize="sm">
          <Menu>
            <MenuButton as={Button} size="sm" variant="outline" leftIcon={<DownloadIcon />} rightIcon={<ChevronDownIcon />}>
              Export
            </MenuButton>
            <MenuList>
              <MenuItem as="a" href={exportUrl("/cves.csv", exportParams)}>
                CSV
              </MenuItem>
              <MenuItem as="a" href={exportUrl("/cves.json", exportParams)}>
                JSON
              </MenuItem>
              <MenuItem as="a" href={exportUrl("/cves.rss", exportParams)}>
                RSS
              </MenuItem>
            </MenuList>
          </Menu>
          <Link href={exportUrl("/cves.csv", exportParams)}>CSV</Link>
          <Link href={exportUrl("/cves.json", exportParams)}>JSON</Link>
          <Link href={exportUrl("/cves.rss", exportParams)} isExternal>
            RSS
          </Link>
        </HStack>
      </HStack>
      <Collapse in={advancedOpen}>
        <HStack mt={3} spacing={3}>
          <FormControl maxW="14rem">
            <FormLabel fontSize="xs">CVE published after</FormLabel>
            <Input
              aria-label="CVE published after"
              type="date"
              background={inputBackground}
              value={params.get("date_after") ?? ""}
              onChange={(event) => update({ date_after: event.target.value || null })}
            />
          </FormControl>
          <FormControl maxW="14rem">
            <FormLabel fontSize="xs">CVE published before</FormLabel>
            <Input
              aria-label="CVE published before"
              type="date"
              background={inputBackground}
              value={params.get("date_before") ?? ""}
              onChange={(event) => update({ date_before: event.target.value || null })}
            />
          </FormControl>
        </HStack>
      </Collapse>
      <HStack mt={3} spacing={3} color={muted} fontSize="sm" flexWrap="wrap">
        <Text color={countColor} fontWeight="700">
          {total.toLocaleString()} {grouped ? (total === 1 ? "CVE" : "CVEs") : total === 1 ? "record" : "records"} found
        </Text>
        <Text>
          {grouped ? "Grouped by CVE (one row per vulnerability)" : "One row per CVE, package, and release"}
        </Text>
        <Hint label="Filters apply before the rows are grouped. A CVE stays in the list when any matching package or release meets the filter. The count is distinct CVE identifiers. The status describes only those matching records.">
          <InfoOutlineIcon tabIndex={0} aria-label="About the result count" />
        </Hint>
      </HStack>
      {loading ? (
        <Spinner mt={8} color={COLOR_RESF_GREEN} />
      ) : error ? (
        <Text mt={8}>Failed to load CVEs.</Text>
      ) : (
        <Box mt={3} bg={tableBg} overflowX="auto" borderWidth="1px" borderColor={borderColor} borderRadius="lg">
          <Table size="sm">
            <Thead>
              {grouped ? (
                <Tr>
                  <Th w="36px" />
                  <SortHeader label="CVE" column="cve" />
                  <Th>Summary</Th>
                  <SortHeader label="Vendor severity" column="severity" tooltip={VENDOR_SEVERITY_HINT} />
                  <SortHeader
                    label="CVSS v3"
                    column="cvss"
                    tooltip="Highest CVSS v3 score stored on NVD or, if NVD has none, on a Rocky advisory. It can differ from the vendor severity."
                  />
                  <SortHeader label="Affected releases" column="product" />
                  <SortHeader label="Remediation status" column="status" />
                  <SortHeader label="Published" column="published" />
                </Tr>
              ) : (
                <Tr>
                  <SortHeader label="CVE" column="cve" />
                  <SortHeader label="Vendor severity" column="severity" />
                  <Th>
                    <Hint label="Band for the CVSS v3 score stored on NVD or, if NVD has none, on the Rocky advisory. It can differ from the vendor severity.">
                      CVSS
                    </Hint>
                  </Th>
                  <SortHeader label="Package" column="component" />
                  <SortHeader label="Release" column="product" />
                  <SortHeader label="Status" column="status" />
                  <Th>
                    <Hint label="Epoch, version, and release identify a source RPM. This column shows the version and release named by the advisory. Epoch 0 is omitted here. The CVE page shows the full EVR and a copyable source RPM filename. This is not a binary RPM.">
                      Fixed source RPM EVR
                    </Hint>
                  </Th>
                  <SortHeader label="CVE published" column="published" />
                </Tr>
              )}
            </Thead>
            <Tbody>{grouped ? <GroupRows rows={groups} /> : <RecordRows rows={rows} />}</Tbody>
          </Table>
        </Box>
      )}
      {!loading && !error && (
        <ExplorerPager page={page} limit={limit} total={total} noun={grouped ? "CVEs" : "records"} />
      )}
    </Box>
  );
}
