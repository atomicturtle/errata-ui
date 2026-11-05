import {
  Box,
  Button,
  Code,
  Drawer,
  DrawerBody,
  DrawerCloseButton,
  DrawerContent,
  DrawerHeader,
  DrawerOverlay,
  Heading,
  HStack,
  Link,
  ListItem,
  Spinner,
  Stack,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  UnorderedList,
  useColorModeValue,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { Link as RouterLink } from "react-router-dom";

import {
  getTrackerFix,
  listTrackerFixes,
  listTrackerProducts,
  type FixDetail,
  type FixRow,
} from "../../api/tracker";
import { COLOR_RESF_GREEN } from "../../styles";
import { severityColor, TrackerFilters } from "./Filters";
import { TrackerPager } from "./CveList";
import { useTrackerParams } from "./params";

export function FixesPage() {
  const { params, update, page, limit } = useTrackerParams();
  const [rows, setRows] = useState<FixRow[]>([]);
  const [total, setTotal] = useState(0);
  const [products, setProducts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [detail, setDetail] = useState<FixDetail>();
  const tableBg = useColorModeValue("white", "gray.800");
  const advisory = params.get("advisory");

  useEffect(() => {
    document.title = "Advisories";
    listTrackerProducts()
      .then((result) => setProducts(result.data.map((item) => item.name)))
      .catch(() => setProducts([]));
  }, []);

  useEffect(() => {
    const query = new URLSearchParams(params);
    query.delete("advisory");
    query.set("page", String(page));
    query.set("limit", String(limit));
    let cancelled = false;
    setLoading(true);
    listTrackerFixes(query)
      .then((result) => {
        if (cancelled) return;
        setRows(result.data);
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
  }, [params, page, limit]);

  useEffect(() => {
    if (!advisory) {
      setDetail(undefined);
      return;
    }
    let cancelled = false;
    getTrackerFix(advisory)
      .then((result) => {
        if (!cancelled) setDetail(result);
      })
      .catch(() => {
        if (!cancelled) setDetail(undefined);
      });
    return () => {
      cancelled = true;
    };
  }, [advisory]);

  async function copyLink() {
    const url = new URL(window.location.href);
    if (advisory) url.searchParams.set("advisory", advisory);
    await navigator.clipboard.writeText(url.toString());
  }

  return (
    <Box p={4}>
      <TrackerFilters
        products={products}
        exportPath="/fixes"
        placeholder="Advisory, CVE, package..."
        showType
        showArch
      />
      {loading ? (
        <Spinner mt={8} color={COLOR_RESF_GREEN} />
      ) : error ? (
        <Text mt={8}>Failed to load fixes.</Text>
      ) : (
        <Box mt={4} bg={tableBg} overflowX="auto">
          <Table size="sm">
            <Thead>
              <Tr>
                <Th>Advisory</Th>
                <Th>Product</Th>
                <Th>Component</Th>
                <Th>Severity</Th>
                <Th>Type</Th>
                <Th>Published</Th>
              </Tr>
            </Thead>
            <Tbody>
              {rows.map((row) => (
                <Tr key={`${row.advisory}-${row.product}`}>
                  <Td>
                    <Button
                      variant="link"
                      onClick={() => update({ advisory: row.advisory }, false)}
                    >
                      {row.advisory}
                    </Button>
                  </Td>
                  <Td>{row.product}</Td>
                  <Td>
                    {row.component || "—"}
                    {row.version ? ` ${row.version}` : ""}
                  </Td>
                  <Td>
                    <Text color={`${severityColor(row.severity)}.500`}>{row.severity}</Text>
                  </Td>
                  <Td>{row.type}</Td>
                  <Td>{row.published || "—"}</Td>
                </Tr>
              ))}
              {!rows.length && (
                <Tr>
                  <Td colSpan={6}>No fixes match these filters.</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </Box>
      )}
      <TrackerPager page={page} limit={limit} total={total} />
      <Drawer
        isOpen={Boolean(advisory)}
        placement="right"
        size="md"
        onClose={() => update({ advisory: null }, false)}
      >
        <DrawerOverlay />
        <DrawerContent>
          <DrawerCloseButton />
          <DrawerHeader>{detail?.advisory || advisory}</DrawerHeader>
          <DrawerBody>
            {!detail ? (
              <Spinner color={COLOR_RESF_GREEN} />
            ) : (
              <Stack spacing={4}>
                <Text>{detail.title}</Text>
                <HStack>
                  <Button size="sm" onClick={() => void copyLink()}>
                    Copy page link
                  </Button>
                  <Button
                    as={RouterLink}
                    size="sm"
                    to={`/${encodeURIComponent(detail.advisory)}`}
                  >
                    Open as a page
                  </Button>
                </HStack>
                {detail.releases.map((release) => (
                  <Box key={release.product}>
                    <Heading size="sm">{release.product}</Heading>
                    <Text mt={2}>How to fix</Text>
                    <Code display="block" whiteSpace="pre" p={2}>
                      {release.updateCommand}
                    </Code>
                    {release.ovalUrl && (
                      <Link href={release.ovalUrl} isExternal>
                        OVAL
                      </Link>
                    )}
                    <Heading size="xs" mt={3}>
                      Updated packages
                    </Heading>
                    <UnorderedList>
                      {release.packages.map((pkg) => (
                        <ListItem key={pkg}>{pkg}</ListItem>
                      ))}
                    </UnorderedList>
                  </Box>
                ))}
                <Link href={detail.csafUrl} isExternal>
                  CSAF
                </Link>
                <Heading size="sm">Changelog</Heading>
                <UnorderedList>
                  {detail.changelog.map((line) => (
                    <ListItem key={line}>{line}</ListItem>
                  ))}
                </UnorderedList>
                <Heading size="sm">CVEs</Heading>
                <UnorderedList>
                  {detail.cves.map((cve) => (
                    <ListItem key={cve}>
                      <Link as={RouterLink} to={`/cves/${encodeURIComponent(cve)}`}>
                        {cve}
                      </Link>
                    </ListItem>
                  ))}
                </UnorderedList>
              </Stack>
            )}
          </DrawerBody>
        </DrawerContent>
      </Drawer>
    </Box>
  );
}
