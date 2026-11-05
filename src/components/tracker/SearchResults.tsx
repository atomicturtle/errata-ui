import { Box, Heading, Link, ListItem, Stack, Text, UnorderedList } from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { Link as RouterLink, useSearchParams } from "react-router-dom";

import {
  listTrackerCves,
  listTrackerFixes,
  type CveRow,
  type FixRow,
} from "../../api/tracker";

export function SearchResults() {
  const [params] = useSearchParams();
  const q = params.get("q") ?? "";
  const [cves, setCves] = useState<CveRow[]>([]);
  const [cveTotal, setCveTotal] = useState(0);
  const [fixes, setFixes] = useState<FixRow[]>([]);
  const [fixTotal, setFixTotal] = useState(0);

  useEffect(() => {
    document.title = q ? `Search ${q}` : "Search";
    if (!q) return;
    const query = new URLSearchParams({ q, limit: "8" });
    listTrackerCves(query)
      .then((result) => {
        setCves(result.data);
        setCveTotal(result.meta.total);
      })
      .catch(() => {
        setCves([]);
        setCveTotal(0);
      });
    listTrackerFixes(query)
      .then((result) => {
        setFixes(result.data);
        setFixTotal(result.meta.total);
      })
      .catch(() => {
        setFixes([]);
        setFixTotal(0);
      });
  }, [q]);

  return (
    <Box p={4} maxW="960px">
      <Heading size="md">Results for “{q}”</Heading>
      <Stack spacing={6} mt={4}>
        <Box>
          <Heading size="sm">Vulnerabilities ({cveTotal.toLocaleString()})</Heading>
          <UnorderedList mt={2}>
            {cves.map((row) => (
              <ListItem key={`${row.cve}-${row.product}-${row.component}`}>
                <Link as={RouterLink} to={cveHref(row)}>
                  {row.cve}
                </Link>{" "}
                {row.product} {row.component || ""} {row.status}
              </ListItem>
            ))}
            {!cves.length && <ListItem>No CVE rows.</ListItem>}
          </UnorderedList>
          <Link as={RouterLink} to={`/cves?q=${encodeURIComponent(q)}`}>
            All vulnerability matches
          </Link>
        </Box>
        <Box>
          <Heading size="sm">Advisories ({fixTotal.toLocaleString()})</Heading>
          <UnorderedList mt={2}>
            {fixes.map((row) => (
              <ListItem key={`${row.advisory}-${row.product}`}>
                <Link as={RouterLink} to={`/${encodeURIComponent(row.advisory)}`}>
                  {row.advisory}
                </Link>{" "}
                {row.product} {row.title || ""}
              </ListItem>
            ))}
            {!fixes.length && <ListItem>No advisories.</ListItem>}
          </UnorderedList>
          <Link as={RouterLink} to={`/fixes?q=${encodeURIComponent(q)}`}>
            All advisory matches
          </Link>
        </Box>
        <Text fontSize="sm">
          Package names are matched as source packages on{" "}
          <Link as={RouterLink} to={`/packages?q=${encodeURIComponent(q)}`}>
            Packages
          </Link>
          . A source package is not a binary RPM.
        </Text>
      </Stack>
    </Box>
  );
}

function cveHref(row: CveRow): string {
  const query = new URLSearchParams();
  if (row.product) query.set("product", row.product);
  if (row.component) query.set("component", row.component);
  if (row.version) query.set("version", row.version);
  const suffix = query.toString();
  return suffix
    ? `/cves/${encodeURIComponent(row.cve)}?${suffix}`
    : `/cves/${encodeURIComponent(row.cve)}`;
}
