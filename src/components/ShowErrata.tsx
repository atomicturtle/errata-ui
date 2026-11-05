import { CheckCircleIcon } from "@chakra-ui/icons";
import {
  Alert,
  AlertDescription,
  AlertIcon,
  AlertTitle,
  Badge,
  Box,
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  Code,
  Heading,
  HStack,
  Link,
  ListItem,
  Spinner,
  Tab,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  Text,
  UnorderedList,
  useColorModeValue,
  VStack,
  SimpleGrid,
} from "@chakra-ui/react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useParams, Link as RouterLink } from "react-router-dom";

import { getAdvisory } from "../api/client";
import type { V2Advisory } from "../api/types";
import {
  cvssScoreToSeverity,
  nvdDetailUrl,
  parseCvss3Metrics,
  parseScore,
  pickPrimaryNvd,
  severityColor,
} from "../lib/nvd";
import { safeHttpUrl } from "../lib/safeHttpUrl";
import { reqap } from "../lib/reqap";
import { COLOR_RESF_GREEN } from "../styles";
import { typeToText } from "./enumToText";
import {
  VulnerabilityDetails,
  useNvdCves,
} from "./VulnerabilityDetails";
import {
  CvssBadge,
  EpssMiniBar,
  ErrataMetricsStrip,
  ErrataTitleShield,
  ExploitMaturityBadge,
} from "./VulnBadges";

function formatDate(raw?: string | null): string {
  if (!raw) return "—";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString();
}

function primaryPackageName(errata: V2Advisory): string | null {
  for (const product of Object.keys(errata.rpms ?? {})) {
    const src = errata.rpms?.[product]?.nvras?.find((x) => isSourceRpm(x));
    if (!src) continue;
    return splitNevra(src)?.name ?? null;
  }
  return null;
}

function collectArches(errata: V2Advisory): string[] {
  const arches = new Set<string>();
  for (const product of Object.keys(errata.rpms ?? {})) {
    for (const nvra of errata.rpms?.[product]?.nvras ?? []) {
      if (nvra.includes(".src.rpm")) continue;
      const m = nvra.match(/\.([^.]+)\.rpm$/);
      if (m?.[1]) arches.add(m[1]);
    }
  }
  return [...arches].sort();
}

function packageCount(errata: V2Advisory): number {
  let n = 0;
  for (const product of Object.keys(errata.rpms ?? {})) {
    n += errata.rpms?.[product]?.nvras?.length ?? 0;
  }
  return n;
}

const NEVRA_RE = /^(.+)-(\d+):([^-]+)-([^-]+)\.([^.]+)\.rpm$/;

function splitNevra(nevra: string): {
  name: string;
  epoch: string;
  version: string;
  release: string;
  arch: string;
} | null {
  const match = NEVRA_RE.exec(nevra);
  if (!match) return null;
  return {
    name: match[1],
    epoch: match[2],
    version: match[3],
    release: match[4],
    arch: match[5],
  };
}

function isSourceRpm(nevra: string): boolean {
  return nevra.includes(".src.rpm") || nevra.endsWith(".src");
}

/** Matches kernel-debuginfo-common-x86_64 and foo-debugsource, not kernel-debug. */
const DEBUG_PACKAGE_RE = /-debug(info|source)(-|$)/;

/** One spec per package name and EVR: dnf picks the arch, so per-arch NVRAs collapse. */
function updateCommand(nvras: string[]): string | null {
  const specs = new Set<string>();
  for (const nvra of nvras) {
    if (isSourceRpm(nvra)) continue;
    const parsed = splitNevra(nvra);
    if (!parsed || !/^[A-Za-z0-9._+-]+$/.test(parsed.name)) continue;
    if (DEBUG_PACKAGE_RE.test(parsed.name)) continue;
    specs.add(`${parsed.name}-${parsed.epoch}:${parsed.version}-${parsed.release}`);
  }
  if (!specs.size || specs.size > 8) return null;
  return `dnf update ${[...specs].join(" ")}`;
}

function referenceLabel(ticket: string, sourceLink: string, sourceBy: string): string {
  if (sourceLink.includes("bugzilla.redhat.com/")) {
    return `Red Hat Bugzilla #${ticket}`;
  }
  if (sourceLink.includes("issues.redhat.com/")) {
    return `Red Hat issue ${ticket}`;
  }
  return [sourceBy, ticket].filter(Boolean).join(" ");
}

function SideRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <HStack align="flex-start" justify="space-between" spacing={3} w="100%">
      <Text fontSize="sm" color="gray.500" flexShrink={0}>
        {label}
      </Text>
      <Box fontSize="sm" textAlign="right" minW={0}>
        {children}
      </Box>
    </HStack>
  );
}

function TimelineItem({
  label,
  date,
  done,
}: {
  label: string;
  date?: string | null;
  done: boolean;
}) {
  const muted = useColorModeValue("gray.500", "gray.400");
  return (
    <HStack align="flex-start" spacing={3}>
      <CheckCircleIcon
        mt="2px"
        color={done ? COLOR_RESF_GREEN : "gray.500"}
        boxSize={4}
      />
      <Box>
        <Text fontSize="sm" fontWeight="medium">
          {label}
        </Text>
        <Text fontSize="xs" color={muted}>
          {date ? formatDate(date) : "—"}
        </Text>
      </Box>
    </HStack>
  );
}

export const ShowErrata = () => {
  const { id } = useParams<{ id: string }>();

  const cardBg = useColorModeValue("white", "gray.800");
  const sideBg = useColorModeValue("gray.50", "gray.900");
  const borderColor = useColorModeValue("gray.200", "gray.600");
  const linkBlue = useColorModeValue("blue.600", "blue.300");
  const linkPurple = useColorModeValue("purple.600", "purple.300");
  const muted = useColorModeValue("gray.600", "gray.400");

  const [errata, setErrata] = useState<V2Advisory>();
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  const [tabIndex, setTabIndex] = useState(0);

  const cveNames = useMemo(
    () => (errata?.cves ?? []).map((c) => c.name).filter(Boolean),
    [errata]
  );
  const {
    items: nvdItems,
    loading: nvdLoading,
    failed: nvdFailed,
    primary: nvdPrimary,
  } = useNvdCves(cveNames);

  const primary = nvdPrimary ?? pickPrimaryNvd(nvdItems);
  const kevListed = nvdItems.some((i) => i.kev_listed);
  const pkgName = errata ? primaryPackageName(errata) : null;
  const arches = errata ? collectArches(errata) : [];
  const pkgCount = errata ? packageCount(errata) : 0;
  const refCount = errata?.references?.length ?? 0;
  const cveCount = errata?.cves?.length ?? 0;
  const fixCount = errata?.fixes?.length ?? 0;
  const hasReferences = refCount > 0 || fixCount > 0 || Boolean(errata?.source);
  const referenceTotal = refCount + fixCount + (errata?.source ? 1 : 0);
  const showTechnical =
    cveNames.length > 0 ||
    Boolean(errata?.rebootSuggested) ||
    Boolean(errata?.restartSuggested);

  const earliestCvePublished = useMemo(() => {
    const dates = nvdItems
      .map((i) => i.published_at)
      .filter(Boolean)
      .map((d) => new Date(d as string).getTime())
      .filter((t) => !Number.isNaN(t));
    if (!dates.length) return null;
    return new Date(Math.min(...dates)).toISOString();
  }, [nvdItems]);

  const nvdById = useMemo(() => {
    const m = new Map<string, (typeof nvdItems)[0]>();
    for (const row of nvdItems) m.set(row.cve_id.toUpperCase(), row);
    return m;
  }, [nvdItems]);

  useEffect(() => {
    if (id) document.title = id;
    setTabIndex(0);
    if (!id) return;
    const fetchData = async () => {
      setIsLoading(true);
      const [err, res] = await reqap(() => getAdvisory(id));
      setIsLoading(false);
      if (err || !res) {
        setIsError(true);
        setErrata(undefined);
        return;
      }
      setIsError(false);
      setErrata(res.advisory);
    };
    fetchData();
  }, [id]);

  return (
    <Box
      w="100%"
      h="100%"
      display="flex"
      flexDirection="column"
      p={4}
      alignItems="stretch"
      maxWidth="1500px"
      m="auto"
    >
      <Breadcrumb mb={4}>
        <BreadcrumbItem>
          <BreadcrumbLink as={RouterLink} to="/">
            Rocky Linux Errata
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbItem>
          <BreadcrumbLink isCurrentPage>{id}</BreadcrumbLink>
        </BreadcrumbItem>
      </Breadcrumb>
      {isLoading ? (
        <Spinner
          m="auto"
          size="xl"
          alignSelf="center"
          color={COLOR_RESF_GREEN}
          thickness="3px"
        />
      ) : isError ? (
        <Alert
          status="error"
          m="auto"
          flexDirection="column"
          width="300px"
          borderRadius="md"
        >
          <AlertIcon mr="0" />
          <AlertTitle>Something has gone wrong</AlertTitle>
          <AlertDescription>Failed to load errata</AlertDescription>
        </Alert>
      ) : (
        errata && (
          <>
            {/* Header */}
            <Box backgroundColor={cardBg} py={4} px={{ base: 4, md: 6 }} mb={3}>
              <HStack align="flex-start" spacing={3} mb={2}>
                <ErrataTitleShield />
                <Box flex="1" minW={0}>
                  <Text fontSize={{ base: "xl", md: "2xl" }} fontWeight="bold">
                    {errata.name}
                  </Text>
                  <Text fontSize="md" color={muted} mt={0.5}>
                    {errata.synopsis}
                  </Text>
                  <HStack mt={2} spacing={2} flexWrap="wrap">
                    {errata.type === "TYPE_SECURITY" && (
                      <Badge colorScheme="red">SECURITY UPDATE</Badge>
                    )}
                    {errata.type !== "TYPE_SECURITY" && (
                      <Badge
                        colorScheme={errata.type === "TYPE_BUGFIX" ? "green" : "blue"}
                      >
                        {typeToText(errata.type).toUpperCase()}
                      </Badge>
                    )}
                    <Text fontSize="xs" color="gray.500">
                      {errata.source ? "Upstream advisory published" : "Published"}{" "}
                      {formatDate(errata.publishedAt)}
                      {errata.rockyPublishedAt
                        ? ` · Rocky Linux advisory published ${formatDate(errata.rockyPublishedAt)}`
                        : ""}
                    </Text>
                  </HStack>
                  {errata.source && (
                    <Text fontSize="xs" mt={2} color="gray.500">
                      Source:{" "}
                      <Link
                        href={safeHttpUrl(errata.source.url)}
                        isExternal
                        color={linkBlue}
                        _visited={{ color: linkPurple }}
                      >
                        {errata.source.vendor} {errata.source.name}
                      </Link>
                      , used under{" "}
                      <Link
                        href={safeHttpUrl(errata.source.licenseUrl)}
                        isExternal
                        color={linkBlue}
                        _visited={{ color: linkPurple }}
                      >
                        {errata.source.license}
                      </Link>
                      , with modifications.
                    </Text>
                  )}
                </Box>
              </HStack>

              {cveNames.length > 0 && (
                <Box mt={4} pt={4} borderTopWidth="1px" borderColor={borderColor}>
                  {primary && cveNames.length > 1 && (
                    <Text fontSize="xs" color={muted} mb={2}>
                      NVD scores for {primary.cve_id}. Other CVEs on this advisory are listed
                      under Vulnerabilities.
                    </Text>
                  )}
                  <ErrataMetricsStrip primary={primary} />
                </Box>
              )}
            </Box>

            <Tabs
              backgroundColor={cardBg}
              p="2"
              index={tabIndex}
              onChange={setTabIndex}
            >
              <TabList flexWrap="wrap">
                <Tab>Overview</Tab>
                {cveCount > 0 && <Tab>Vulnerabilities ({cveCount})</Tab>}
                <Tab>Packages & Fixes{pkgCount > 0 ? ` (${pkgCount})` : ""}</Tab>
                {hasReferences && <Tab>References ({referenceTotal})</Tab>}
                {showTechnical && <Tab>Technical Details</Tab>}
              </TabList>

              <Box
                display="flex"
                flexDir="row"
                alignItems="stretch"
                flexWrap="wrap"
                gap={4}
                justifyContent="space-between"
              >
                <TabPanels flex="1" minW={{ base: "100%", lg: "0" }} px="2">
                  {/* Overview */}
                  <TabPanel px={{ base: 2, md: 4 }}>
                    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={6}>
                      <Box gridColumn={{ xl: "span 2" }}>
                        <Heading as="h2" size="md">
                          Summary
                        </Heading>
                        {errata.topic?.split("\n").map((p, i) => (
                          <Text key={i} mt={2}>
                            {p}
                          </Text>
                        ))}
                        <Heading as="h2" size="md" mt={4}>
                          Description
                        </Heading>
                        {errata.description?.split("\n").map((p, i) => (
                          <Text key={i} mt={2}>
                            {p}
                          </Text>
                        ))}
                      </Box>

                      <VStack align="stretch" spacing={4}>
                        {cveCount > 0 && (
                          <Box
                            borderWidth="1px"
                            borderColor={borderColor}
                            borderRadius="md"
                            p={4}
                            bg={sideBg}
                          >
                            <Heading as="h3" size="sm" mb={3}>
                              CVE Summary
                            </Heading>
                            <VStack align="stretch" spacing={3}>
                              {errata.cves?.map((cve, idx) => {
                                const nvd = nvdById.get(cve.name.toUpperCase());
                                const score =
                                  parseScore(nvd?.cvss_v3_score) ??
                                  parseScore(cve.cvss3BaseScore);
                                const sev = cvssScoreToSeverity(score);
                                return (
                                  <Box key={idx}>
                                    <HStack justify="space-between" spacing={2}>
                                      <Link
                                        href={safeHttpUrl(
                                          cve.sourceLink ||
                                            nvdDetailUrl(cve.name)
                                        )}
                                        isExternal
                                        color={linkBlue}
                                        fontSize="sm"
                                        fontWeight="semibold"
                                      >
                                        {cve.name}
                                      </Link>
                                      <CvssBadge score={score} severity={sev} />
                                    </HStack>
                                    {nvd?.description && (
                                      <Text fontSize="xs" color={muted} mt={1} noOfLines={2}>
                                        {nvd.description}
                                      </Text>
                                    )}
                                  </Box>
                                );
                              })}
                            </VStack>
                          </Box>
                        )}
                        <Box
                          borderWidth="1px"
                          borderColor={borderColor}
                          borderRadius="md"
                          p={4}
                          bg={sideBg}
                        >
                          <Heading as="h3" size="sm" mb={3}>
                            Affected Products
                          </Heading>
                          <UnorderedList pl={4} m={0}>
                            {(errata.affectedProducts ?? []).map((p, idx) => (
                              <ListItem key={idx} fontSize="sm">
                                {p}
                              </ListItem>
                            ))}
                          </UnorderedList>
                          {arches.length > 0 && (
                            <Text fontSize="xs" color={muted} mt={2}>
                              Architectures: {arches.join(", ")}
                            </Text>
                          )}
                        </Box>
                      </VStack>
                    </SimpleGrid>
                  </TabPanel>

                  {/* Vulnerabilities */}
                  {cveCount > 0 && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <Heading as="h2" size="md" mb={4}>
                        Vulnerabilities ({cveCount})
                      </Heading>
                      <VStack align="stretch" spacing={4}>
                        {errata.cves?.map((cve, idx) => {
                          const nvd = nvdById.get(cve.name.toUpperCase());
                          const score =
                            parseScore(nvd?.cvss_v3_score) ??
                            parseScore(cve.cvss3BaseScore);
                          const sev = cvssScoreToSeverity(score);
                          const metrics = parseCvss3Metrics(
                            nvd?.cvss_v3_vector || cve.cvss3ScoringVector
                          );
                          return (
                            <Box
                              key={idx}
                              borderWidth="1px"
                              borderColor={borderColor}
                              borderRadius="md"
                              p={4}
                            >
                              <HStack justify="space-between" mb={2} flexWrap="wrap" gap={2}>
                                <Link
                                  href={safeHttpUrl(
                                    cve.sourceLink || nvdDetailUrl(cve.name)
                                  )}
                                  isExternal
                                  color={linkBlue}
                                  fontWeight="bold"
                                >
                                  {cve.name}
                                </Link>
                                <HStack>
                                  <Text
                                    fontSize="sm"
                                    fontWeight="bold"
                                    color={severityColor(sev)}
                                  >
                                    {sev}
                                  </Text>
                                  <CvssBadge score={score} severity={sev} />
                                </HStack>
                              </HStack>
                              {(nvd?.description || cve.cwe) && (
                                <Text fontSize="sm" color={muted} mb={2}>
                                  {nvd?.description || `CWE: ${cve.cwe}`}
                                </Text>
                              )}
                              <HStack spacing={4} flexWrap="wrap" fontSize="xs" color={muted}>
                                <Text>AV: {metrics["Attack Vector"] || "—"}</Text>
                                <Text>AC: {metrics["Attack Complexity"] || "—"}</Text>
                                <Text>PR: {metrics["Privileges Required"] || "—"}</Text>
                                <Text>UI: {metrics["User Interaction"] || "—"}</Text>
                                <Box minW="100px">
                                  <EpssMiniBar score={nvd?.epss_score} />
                                </Box>
                                <ExploitMaturityBadge label={nvd?.exploit_maturity} />
                              </HStack>
                            </Box>
                          );
                        })}
                      </VStack>
                    </TabPanel>
                  )}

                  {/* Packages & Fixes */}
                  <TabPanel px={{ base: 2, md: 4 }}>
                    <Heading as="h2" size="md" mb={2}>
                      Packages & Fixes
                    </Heading>
                    <Text fontSize="sm" color={muted} mb={4}>
                      These are the RPM builds stored on the advisory. The
                      advisory publication time is not an RPM availability time.
                    </Text>
                    {pkgCount === 0 ? (
                      <Text>
                        Fixed version unavailable. This advisory record does
                        not include an RPM build.
                      </Text>
                    ) : (
                      <VStack align="stretch" spacing={6}>
                        {Object.keys(errata.rpms ?? {}).map((product) => {
                          const nvras = errata.rpms?.[product]?.nvras ?? [];
                          const sources = nvras.filter((x) => isSourceRpm(x));
                          const binaries = nvras.filter((x) => !isSourceRpm(x));
                          const repos = errata.rpms?.[product]?.repositories ?? [];
                          const command = updateCommand(nvras);
                          return (
                            <Box
                              key={product}
                              borderWidth="1px"
                              borderColor={borderColor}
                              borderRadius="md"
                              p={4}
                            >
                              <Text fontSize="xs" color={muted} textTransform="uppercase">
                                Affected release
                              </Text>
                              <Heading as="h3" size="sm" mb={3}>
                                {product}
                              </Heading>
                              <Text fontSize="xs" color={muted} textTransform="uppercase">
                                Source package
                              </Text>
                              {sources.length > 0 ? (
                                sources.map((x) => (
                                  <Text key={x} fontFamily="mono" fontSize="sm" mb={2}>
                                    {x}
                                  </Text>
                                ))
                              ) : (
                                <Text fontSize="sm" mb={2}>
                                  Source package not recorded.
                                </Text>
                              )}
                              <Text fontSize="xs" color={muted} textTransform="uppercase" mt={2}>
                                Updated binary RPMs
                              </Text>
                              {binaries.length > 0 ? (
                                <Box maxH="420px" overflowY="auto" mb={3}>
                                  {binaries.map((x) => (
                                    <Text key={x} fontFamily="mono" fontSize="sm">
                                      {x}
                                    </Text>
                                  ))}
                                </Box>
                              ) : (
                                <Text fontSize="sm" mb={3}>
                                  Fixed version unavailable. No binary RPM is
                                  recorded for this release.
                                </Text>
                              )}
                              <Text fontSize="xs" color={muted} textTransform="uppercase">
                                Repository
                              </Text>
                              <Text fontSize="sm" mb={3}>
                                {repos.length > 0
                                  ? repos.join(", ")
                                  : "Repository not recorded for these packages."}
                              </Text>
                              {(errata.cves?.length ?? 0) > 0 && (
                                <>
                                  <Text fontSize="xs" color={muted} textTransform="uppercase">
                                    Associated CVEs
                                  </Text>
                                  <UnorderedList pl={4} mb={3} spacing={1}>
                                    {errata.cves?.map((cve) => (
                                      <ListItem key={cve.name} fontSize="sm">
                                        <Link
                                          as={RouterLink}
                                          to={`/cves/${encodeURIComponent(cve.name)}`}
                                          color={linkBlue}
                                        >
                                          {cve.name}
                                        </Link>
                                        {cve.sourceLink ? (
                                          <>
                                            {" "}
                                            <Link
                                              href={safeHttpUrl(cve.sourceLink)}
                                              isExternal
                                              color={linkBlue}
                                              fontSize="xs"
                                            >
                                              (upstream)
                                            </Link>
                                          </>
                                        ) : null}
                                      </ListItem>
                                    ))}
                                  </UnorderedList>
                                </>
                              )}
                              <Text fontSize="xs" color={muted} textTransform="uppercase">
                                Remediation
                              </Text>
                              {errata.solution ? (
                                <Text fontSize="sm" mb={2}>
                                  {errata.solution}
                                </Text>
                              ) : null}
                              {command ? (
                                <>
                                  <Code display="block" p={2} fontSize="sm" mb={2}>
                                    {command}
                                  </Code>
                                  <Text fontSize="xs" color={muted}>
                                    The command names the binary builds stored
                                    on this advisory. It does not confirm that
                                    a repository currently serves them.
                                  </Text>
                                </>
                              ) : binaries.length > 0 ? (
                                <Text fontSize="sm">
                                  Install the binary RPMs listed above. Each
                                  line is the exact NEVRA stored on this
                                  advisory.
                                </Text>
                              ) : null}
                            </Box>
                          );
                        })}
                      </VStack>
                    )}
                  </TabPanel>

                  {hasReferences && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <Heading as="h2" size="md" mb={4}>
                        References
                      </Heading>
                      <VStack align="stretch" spacing={5}>
                        {errata.source && (
                          <Box>
                            <Text fontSize="xs" color={muted} textTransform="uppercase">
                              Upstream advisory
                            </Text>
                            <Link
                              href={safeHttpUrl(errata.source.url)}
                              isExternal
                              color={linkBlue}
                              fontWeight="semibold"
                            >
                              {errata.source.vendor} {errata.source.name}
                            </Link>
                          </Box>
                        )}
                        {fixCount > 0 && (
                          <Box>
                            <Text fontSize="xs" color={muted} textTransform="uppercase" mb={1}>
                              Upstream issue references
                            </Text>
                            <Text fontSize="sm" color={muted} mb={2}>
                              These identify upstream bugs. They are not RPM
                              builds.
                            </Text>
                            <UnorderedList pl={4} spacing={1}>
                              {errata.fixes?.map((fix, idx) => (
                                <ListItem key={`${fix.ticket}-${idx}`}>
                                  {fix.sourceLink ? (
                                    <Link
                                      href={safeHttpUrl(fix.sourceLink)}
                                      isExternal
                                      color={linkBlue}
                                    >
                                      {referenceLabel(
                                        fix.ticket,
                                        fix.sourceLink,
                                        fix.sourceBy
                                      )}
                                    </Link>
                                  ) : (
                                    referenceLabel(fix.ticket, "", fix.sourceBy)
                                  )}
                                  {fix.description ? ` — ${fix.description}` : ""}
                                </ListItem>
                              ))}
                            </UnorderedList>
                          </Box>
                        )}
                        {refCount > 0 && (
                          <Box>
                            <Text fontSize="xs" color={muted} textTransform="uppercase" mb={1}>
                              Other references
                            </Text>
                            <UnorderedList pl={4} spacing={1}>
                              {errata.references?.map((x, idx) => (
                                <ListItem key={idx}>{x}</ListItem>
                              ))}
                            </UnorderedList>
                          </Box>
                        )}
                      </VStack>
                    </TabPanel>
                  )}

                  {showTechnical && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <Heading as="h2" size="md" mb={4}>
                        Technical Details
                      </Heading>
                      {cveNames.length > 0 && (
                        <VulnerabilityDetails
                          cveNames={cveNames}
                          items={nvdItems}
                          loading={nvdLoading}
                          failed={nvdFailed}
                        />
                      )}
                      <VStack align="stretch" spacing={2} mt={4} fontSize="sm">
                        <Text>
                          Reboot suggested: {errata.rebootSuggested ? "yes" : "no"}
                        </Text>
                        <Text>
                          Restart suggested: {errata.restartSuggested ? "yes" : "no"}
                        </Text>
                        {cveNames.length > 0 && (
                          <Text>
                            CISA KEV:{" "}
                            {nvdLoading
                              ? "…"
                              : kevListed
                                ? "listed"
                                : "not listed"}
                          </Text>
                        )}
                      </VStack>
                    </TabPanel>
                  )}
                </TabPanels>

                {/* Sidebar */}
                <VStack
                  py={4}
                  px={4}
                  alignItems="stretch"
                  minWidth="260px"
                  maxWidth="320px"
                  spacing={4}
                  flexShrink={0}
                  w={{ base: "100%", lg: "300px" }}
                >
                  <Box
                    backgroundColor={sideBg}
                    borderWidth="1px"
                    borderColor={borderColor}
                    borderRadius="md"
                    p={4}
                  >
                    <VStack align="stretch" spacing={3}>
                      <SideRow label="Type">
                        <Badge
                          colorScheme={
                            errata.type === "TYPE_SECURITY"
                              ? "red"
                              : errata.type === "TYPE_BUGFIX"
                                ? "green"
                                : "blue"
                          }
                        >
                          {typeToText(errata.type).toUpperCase()}
                        </Badge>
                      </SideRow>
                      <SideRow label="Release">
                        {(errata.affectedProducts ?? []).join(", ") || "—"}
                      </SideRow>
                      {pkgName && (
                        <SideRow label="Package">
                          <Text fontFamily="mono" fontSize="xs">
                            {pkgName}
                          </Text>
                        </SideRow>
                      )}
                      {arches.length > 0 && (
                        <SideRow label="Architecture">
                          <Text fontSize="xs">{arches.join(", ")}</Text>
                        </SideRow>
                      )}
                      {errata.source && (
                        <SideRow label="Upstream advisory">
                          <Link
                            href={safeHttpUrl(errata.source.url)}
                            isExternal
                            color={linkBlue}
                            _visited={{ color: linkPurple }}
                          >
                            {errata.source.name}
                          </Link>
                        </SideRow>
                      )}
                    </VStack>
                  </Box>

                  {(cveNames.length > 0 ||
                    errata.publishedAt ||
                    errata.rockyPublishedAt) && (
                    <Box
                      backgroundColor={sideBg}
                      borderWidth="1px"
                      borderColor={borderColor}
                      borderRadius="md"
                      p={4}
                    >
                      <Text fontSize="sm" fontWeight="semibold" mb={3}>
                        Timeline
                      </Text>
                      <VStack align="stretch" spacing={3}>
                        {cveNames.length > 0 && (
                          <TimelineItem
                            label="CVE published"
                            date={earliestCvePublished}
                            done={!!earliestCvePublished}
                          />
                        )}
                        {errata.publishedAt && (
                          <TimelineItem
                            label={
                              errata.source
                                ? "Upstream advisory published"
                                : "Advisory published"
                            }
                            date={errata.publishedAt}
                            done
                          />
                        )}
                        {errata.rockyPublishedAt && (
                          <TimelineItem
                            label="Rocky Linux advisory published"
                            date={errata.rockyPublishedAt}
                            done
                          />
                        )}
                      </VStack>
                    </Box>
                  )}
                </VStack>
              </Box>
            </Tabs>
          </>
        )
      )}
    </Box>
  );
};
