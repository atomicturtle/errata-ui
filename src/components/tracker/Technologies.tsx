import {
  Box,
  Link,
  Spinner,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  useColorModeValue,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { Link as RouterLink } from "react-router-dom";

import {
  listTechnologies,
  listTrackerProducts,
  type TechnologyRow,
} from "../../api/tracker";
import { COLOR_RESF_GREEN } from "../../styles";
import { TrackerPager } from "./CveList";
import { TrackerFilters } from "./Filters";
import { useTrackerParams } from "./params";

export function TechnologiesPage() {
  const { params, page, limit } = useTrackerParams();
  const [rows, setRows] = useState<TechnologyRow[]>([]);
  const [total, setTotal] = useState(0);
  const [products, setProducts] = useState<string[]>([]);
  const [eol, setEol] = useState<Record<string, string | null>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const tableBg = useColorModeValue("white", "gray.800");

  useEffect(() => {
    document.title = "Packages";
    listTrackerProducts()
      .then((result) => {
        setProducts(result.data.map((item) => item.name));
        const dates: Record<string, string | null> = {};
        for (const item of result.data) dates[item.name] = item.eolAt;
        setEol(dates);
      })
      .catch(() => setProducts([]));
  }, []);

  useEffect(() => {
    const query = new URLSearchParams(params);
    query.delete("advisory");
    query.set("page", String(page));
    query.set("limit", String(limit));
    let cancelled = false;
    setLoading(true);
    listTechnologies(query)
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

  return (
    <Box p={4}>
      <Text mb={3}>
        Source-package catalog (not in the primary navigation). Each row is the newest source
        version-release seen in a published advisory for that release, plus how many advisories
        name the package. Binary NEVRAs and fixed-package evidence are on the advisory page;
        per-CVE status is under CVEs.
      </Text>
      <TrackerFilters
        products={products}
        exportPath="/technologies"
        placeholder="Package name..."
        showSeverity={false}
        showDates={false}
      />
      {loading ? (
        <Spinner mt={8} color={COLOR_RESF_GREEN} />
      ) : error ? (
        <Text mt={8}>Failed to load packages.</Text>
      ) : (
        <Box mt={4} bg={tableBg} overflowX="auto">
          <Table size="sm">
            <Thead>
              <Tr>
                <Th>Source package</Th>
                <Th>Latest source version</Th>
                <Th>Advisories</Th>
                <Th>Product</Th>
                <Th>EOL</Th>
              </Tr>
            </Thead>
            <Tbody>
              {rows.map((row) => (
                <Tr key={`${row.product}-${row.component}`}>
                  <Td>
                    <Link as={RouterLink} to={`/cves?q=${encodeURIComponent(row.component)}&product=${encodeURIComponent(row.product)}`}>
                      {row.component}
                    </Link>
                  </Td>
                  <Td fontFamily="mono">{row.version || "—"}</Td>
                  <Td>{row.advisoryCount}</Td>
                  <Td>{row.product}</Td>
                  <Td>{row.eolAt || eol[row.product] || "—"}</Td>
                </Tr>
              ))}
              {!rows.length && (
                <Tr>
                  <Td colSpan={5}>No packages match these filters.</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </Box>
      )}
      <TrackerPager page={page} limit={limit} total={total} />
    </Box>
  );
}
