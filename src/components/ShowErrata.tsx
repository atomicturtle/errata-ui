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
    const src = errata.rpms?.[product]?.nvras?.find((x) =>
      x.includes(".src.rpm")
    );
    if (!src) continue;
    const base = src.replace(/\.src\.rpm$/, "");
    const m = base.match(/^(.+)-[^-]+-[^-]+$/);
    return m?.[1] ?? base;
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
            Product Errata
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
                    <Badge
                      colorScheme={
                        errata.type === "TYPE_SECURITY"
                          ? "red"
                          : errata.type === "TYPE_BUGFIX"
                            ? "green"
                            : "blue"
                      }
                    >
                      {errata.type === "TYPE_SECURITY"
                        ? "SECURITY UPDATE"
                        : typeToText(errata.type).toUpperCase()}
                    </Badge>
                    {errata.type === "TYPE_SECURITY" && fixCount > 0 && (
                      <Badge colorScheme="green">BUG FIX</Badge>
                    )}
                    <Text fontSize="xs" color="gray.500">
                      Issued {formatDate(errata.publishedAt)}
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
                {pkgCount > 0 && <Tab>Affected Packages ({pkgCount})</Tab>}
                {refCount > 0 && <Tab>References ({refCount})</Tab>}
                {cveNames.length > 0 && <Tab>CVSS Details</Tab>}
                {fixCount > 0 && <Tab>Fixes ({fixCount})</Tab>}
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
                        {fixCount > 0 && (
                          <>
                            <Heading as="h2" size="md" mt={4}>
                              Bug Fix(es) and Enhancement(s)
                            </Heading>
                            <UnorderedList pl={4} mt={2} spacing={1}>
                              {errata.fixes?.map((x, idx) => (
                                <ListItem key={idx}>
                                  <Link
                                    href={safeHttpUrl(x.sourceLink)}
                                    isExternal
                                    color={linkBlue}
                                    _visited={{ color: linkPurple }}
                                  >
                                    {x.sourceBy} - {x.ticket}
                                  </Link>
                                  {x.description ? ` ${x.description}` : ""}
                                </ListItem>
                              ))}
                            </UnorderedList>
                          </>
                        )}
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

                    {cveNames.length > 0 && (
                      <VulnerabilityDetails
                        cveNames={cveNames}
                        items={nvdItems}
                        loading={nvdLoading}
                        failed={nvdFailed}
                      />
                    )}
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

                  {/* Packages */}
                  {pkgCount > 0 && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <VStack alignItems="flex-start" spacing="6">
                        {Object.keys(errata.rpms ?? {}).map((product) => (
                          <div key={product}>
                            <Heading as="h2" size="lg" mb={4} fontWeight="300">
                              {product}
                            </Heading>
                            <Heading as="h3" size="md" mt={2}>
                              SRPMs
                            </Heading>
                            <UnorderedList pl="4">
                              {errata.rpms?.[product]?.nvras
                                ?.filter((x) => x.includes(".src.rpm"))
                                .map((x) => (
                                  <ListItem key={x}>{x}</ListItem>
                                ))}
                            </UnorderedList>
                            <Heading as="h3" size="md" mt={2}>
                              RPMs
                            </Heading>
                            <UnorderedList pl="4">
                              {errata.rpms?.[product]?.nvras
                                ?.filter((x) => !x.includes(".src.rpm"))
                                .map((x) => (
                                  <ListItem key={x}>{x}</ListItem>
                                ))}
                            </UnorderedList>
                          </div>
                        ))}
                      </VStack>
                    </TabPanel>
                  )}

                  {/* References */}
                  {refCount > 0 && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <Heading as="h2" size="md" mb={3}>
                        References ({refCount})
                      </Heading>
                      <UnorderedList pl={4} spacing={1}>
                        {errata.references?.map((x, idx) => (
                          <ListItem key={idx}>{x}</ListItem>
                        ))}
                      </UnorderedList>
                    </TabPanel>
                  )}

                  {/* CVSS Details */}
                  {cveNames.length > 0 && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <VulnerabilityDetails
                        cveNames={cveNames}
                        items={nvdItems}
                        loading={nvdLoading}
                        failed={nvdFailed}
                      />
                    </TabPanel>
                  )}

                  {/* Fixes */}
                  {fixCount > 0 && (
                    <TabPanel px={{ base: 2, md: 4 }}>
                      <Heading as="h2" size="md" mb={3}>
                        Fixes ({fixCount})
                      </Heading>
                      <UnorderedList pl={4} spacing={1}>
                        {errata.fixes?.map((x, idx) => (
                          <ListItem key={idx}>
                            <Link
                              href={safeHttpUrl(x.sourceLink)}
                              isExternal
                              color={linkBlue}
                              _visited={{ color: linkPurple }}
                            >
                              {x.sourceBy} - {x.ticket}
                            </Link>
                            {x.description ? ` — ${x.description}` : ""}
                          </ListItem>
                        ))}
                      </UnorderedList>
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
                      <SideRow label="References">{refCount || "None"}</SideRow>
                      <SideRow label="Fix State">
                        <Badge colorScheme="green">Fixed</Badge>
                      </SideRow>
                      {errata.source && (
                        <SideRow label="Erratum ID (Upstream)">
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

                  {(earliestCvePublished ||
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
                            label="CVE Published"
                            date={earliestCvePublished}
                            done={!!earliestCvePublished}
                          />
                        )}
                        {errata.source && (
                          <TimelineItem
                            label="Upstream Fix Published"
                            date={errata.publishedAt}
                            done={!!errata.publishedAt}
                          />
                        )}
                        {errata.rockyPublishedAt &&
                          (!errata.publishedAt ||
                            new Date(errata.rockyPublishedAt).getTime() >=
                              new Date(errata.publishedAt).getTime()) && (
                            <TimelineItem
                              label="Rocky Erratum Published"
                              date={errata.rockyPublishedAt}
                              done={!!errata.rockyPublishedAt}
                            />
                          )}
                      </VStack>
                    </Box>
                  )}

                  <Box
                    backgroundColor={sideBg}
                    borderWidth="1px"
                    borderColor={borderColor}
                    borderRadius="md"
                    p={4}
                  >
                    <Text fontSize="sm" fontWeight="semibold" mb={3}>
                      Additional Details
                    </Text>
                    <VStack align="stretch" spacing={3}>
                      <SideRow label="Reboot Required">
                        <Text>{errata.rebootSuggested ? "Yes" : "No"}</Text>
                      </SideRow>
                      <SideRow label="Restart Required">
                        <Text>{errata.restartSuggested ? "Yes" : "No"}</Text>
                      </SideRow>
                      <SideRow label="Live Patching">
                        <Text fontSize="xs">Not Available</Text>
                      </SideRow>
                      {cveNames.length > 0 && (
                        <SideRow label="KEV Catalog">
                          {nvdLoading ? (
                            "…"
                          ) : kevListed ? (
                            <Text as="span" color="orange.400" fontWeight="semibold">
                              Listed
                            </Text>
                          ) : (
                            "Not Listed"
                          )}
                        </SideRow>
                      )}
                      <SideRow label="Status in Rocky Linux">
                        <Badge colorScheme="green" variant="solid">
                          Fix Available
                        </Badge>
                      </SideRow>
                    </VStack>
                  </Box>
                </VStack>
              </Box>
            </Tabs>
          </>
        )
      )}
    </Box>
  );
};
