import {
  AddIcon,
  ArrowLeftIcon,
  ArrowRightIcon,
  MinusIcon,
  SearchIcon,
} from "@chakra-ui/icons";
import {
  Alert,
  AlertDescription,
  AlertIcon,
  AlertTitle,
  Box,
  ButtonGroup,
  FormControl,
  FormLabel,
  HStack,
  IconButton,
  Input,
  InputGroup,
  InputLeftElement,
  Link,
  Select,
  Spinner,
  Stack,
  Table,
  TableColumnHeaderProps,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  useColorModeValue,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { Link as RouterLink, useSearchParams } from "react-router-dom";

import { listAdvisories } from "../api/client";
import type {
  V2Advisory,
  AdvisoryTypeFilterKey,
  AdvisorySeverityFilterKey,
} from "../api/types";
import { AdvisoryTypeEnum, AdvisorySeverityEnum } from "../api/types";
import { reqap } from "../lib/reqap";
import { COLOR_RESF_GREEN } from "../styles";
import { severityToBadge, severityToText, typeToText } from "./enumToText";
import { ADVISORY_ID, CVE_ID } from "./tracker/searchRoute";

const RELEASES = ["Rocky Linux 8", "Rocky Linux 9", "Rocky Linux 10"];

function paramDate(value: string | null, endOfDay: boolean): Date | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return undefined;
  const [year, month, date] = value.split("-").map(Number);
  return endOfDay ? new Date(year, month - 1, date, 23, 59, 59) : new Date(year, month - 1, date);
}

export const Overview = () => {
  const [params] = useSearchParams();
  const initialType = params.get("type");
  const initialSeverity = params.get("severity");
  const initialProduct = params.get("product");
  const inputBackground = useColorModeValue("white", undefined);
  const tableBg = useColorModeValue("white", "gray.800");
  const pagerButtonScheme = useColorModeValue("blackAlpha", "gray");
  const linkBlue = useColorModeValue("blue.600", "blue.300");
  const linkPurple = useColorModeValue("purple.600", "purple.300");

  const [advisories, setAdvisories] = useState<V2Advisory[]>();
  const [lastUpdated, setLastUpdated] = useState<string>();
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);

  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [filtersKeyword, setFiltersKeyword] = useState<string | undefined>(
    params.get("q") || undefined
  );
  const [filterBefore, setFilterBefore] = useState<Date | undefined>(() =>
    paramDate(params.get("before"), true)
  );
  const [filterAfter, setFilterAfter] = useState<Date | undefined>(() =>
    paramDate(params.get("after"), false)
  );
  const [filterProduct, setFilterProduct] = useState<string>(
    initialProduct && RELEASES.includes(initialProduct) ? initialProduct : ""
  );
  const [filtersType, setFiltersType] = useState<AdvisoryTypeFilterKey | undefined>(
    initialType && initialType in AdvisoryTypeEnum
      ? (initialType as AdvisoryTypeFilterKey)
      : undefined
  );
  const [filtersSeverity, setFiltersSeverity] = useState<
    AdvisorySeverityFilterKey | undefined
  >(
    initialSeverity && initialSeverity in AdvisorySeverityEnum
      ? (initialSeverity as AdvisorySeverityFilterKey)
      : undefined
  );

  useEffect(() => {
    document.title = "Rocky Linux Errata";
    const fetchData = async () => {
      setIsLoading(true);
      const [err, res] = await reqap(() =>
        listAdvisories({
          page,
          limit: pageSize,
          keyword: filtersKeyword,
          fetchRelated: false,
          before: filterBefore,
          after: filterAfter,
          product: filterProduct || undefined,
          severity: filtersSeverity
            ? AdvisorySeverityEnum[filtersSeverity]
            : undefined,
          type: filtersType ? AdvisoryTypeEnum[filtersType] : undefined,
        })
      );

      setIsLoading(false);

      if (err || !res) {
        setIsError(true);
        setAdvisories(undefined);
        return;
      }

      setIsError(false);
      setAdvisories(res.advisories);
      setLastUpdated(res.lastUpdated);
      setTotal(res.total ?? 0);
    };

    const timer = setTimeout(() => fetchData(), 500);
    return () => clearTimeout(timer);
  }, [
    pageSize,
    page,
    filtersKeyword,
    filterBefore,
    filterAfter,
    filtersSeverity,
    filterProduct,
    filtersType,
  ]);

  const stickyProps: TableColumnHeaderProps = {
    position: "sticky",
    top: "0px",
    zIndex: "10",
    scope: "col",
  };

  const lastPage = total < pageSize ? 0 : Math.ceil(total / pageSize) - 1;

  const typeFilterKeys = (
    Object.keys(AdvisoryTypeEnum) as AdvisoryTypeFilterKey[]
  ).sort((a, b) => a.localeCompare(b));

  const severityFilterKeys = (
    Object.keys(AdvisorySeverityEnum) as AdvisorySeverityFilterKey[]
  ).sort((a, b) => a.localeCompare(b));

  return (
    <Box
      w="100%"
      h="100%"
      display="flex"
      flexDirection="column"
      p={4}
      alignItems="stretch"
    >
      <Stack
        direction={{ sm: "column", lg: "row" }}
        alignItems={{ sm: "stretch", lg: "flex-end" }}
      >
        <InputGroup>
          <InputLeftElement>
            <SearchIcon />
          </InputLeftElement>
          <Input
            type="search"
            aria-label="Keyword search"
            placeholder="Search advisory, CVE, or package..."
            flexGrow={1}
            width="200px"
            variant="filled"
            borderRadius="0"
            backgroundColor={inputBackground}
            value={filtersKeyword ?? ""}
            onChange={(e) => {
              setPage(0);
              setFiltersKeyword(e.target.value || undefined);
            }}
          />
        </InputGroup>
        <HStack>
          <FormControl width="180px" flexShrink={0} flexGrow={1}>
            <FormLabel fontSize="sm">Type</FormLabel>
            <Select
              aria-label="Type"
              placeholder="All"
              variant="filled"
              background={inputBackground}
              borderRadius="0"
              value={filtersType ?? ""}
              onChange={(e) => {
                const val = e.currentTarget.value as AdvisoryTypeFilterKey | "";
                if (val !== "Security") {
                  setFiltersSeverity(undefined);
                }
                setFiltersType(val || undefined);
              }}
            >
              {typeFilterKeys.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </FormControl>
          {filtersType === "Security" && (
            <FormControl width="180px" flexShrink={0} flexGrow={1}>
              <FormLabel fontSize="sm">Severity</FormLabel>
              <Select
                aria-label="Severity"
                placeholder="All"
                variant="filled"
                background={inputBackground}
                borderRadius="0"
                value={filtersSeverity ?? ""}
                onChange={(e) =>
                  setFiltersSeverity(
                    (e.currentTarget.value as AdvisorySeverityFilterKey) ||
                      undefined
                  )
                }
              >
                {severityFilterKeys.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </FormControl>
          )}
          <FormControl width="180px" flexShrink={0} flexGrow={1}>
            <FormLabel fontSize="sm">Product</FormLabel>
            <Select
              aria-label="Product"
              placeholder="All"
              variant="filled"
              background={inputBackground}
              borderRadius="0"
              value={filterProduct}
              onChange={(e) => setFilterProduct(e.currentTarget.value)}
            >
              {RELEASES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                )
              )}
            </Select>
          </FormControl>
        </HStack>
        <HStack>
          <FormControl width="180px" flexShrink={0} flexGrow={1}>
            <FormLabel fontSize="sm">From</FormLabel>
            <Input
              type="date"
              variant="filled"
              background={inputBackground}
              borderRadius="0"
              max={
                filterBefore
                  ? filterBefore.toLocaleDateString("en-ca")
                  : new Date().toLocaleDateString("en-ca")
              }
              value={filterAfter?.toLocaleDateString("en-ca") || ""}
              onChange={(e) => {
                const newVal = e.currentTarget.value;
                if (!newVal) {
                  setFilterAfter(undefined);
                  return;
                }
                const asDate = new Date(newVal);
                if (isNaN(asDate.getTime())) return;
                const [year, month, date] = newVal.split("-").map(Number);
                setFilterAfter(new Date(year, month - 1, date));
              }}
            />
          </FormControl>
          <FormControl width="180px" flexShrink={0} flexGrow={1}>
            <FormLabel fontSize="sm">To</FormLabel>
            <Input
              type="date"
              variant="filled"
              background={inputBackground}
              borderRadius="0"
              min={filterAfter?.toLocaleDateString("en-ca")}
              max={new Date().toLocaleDateString("en-ca")}
              value={filterBefore?.toLocaleDateString("en-ca") || ""}
              onChange={(e) => {
                const newVal = e.currentTarget.value;
                if (!newVal) {
                  setFilterBefore(undefined);
                  return;
                }
                const asDate = new Date(newVal);
                if (isNaN(asDate.getTime())) return;
                const [year, month, date] = newVal.split("-").map(Number);
                setFilterBefore(new Date(year, month - 1, date, 23, 59, 59));
              }}
            />
          </FormControl>
        </HStack>
      </Stack>
      {filtersKeyword?.trim() && (
        <Text fontSize="sm" mt={2}>
          <Link
            as={RouterLink}
            color={linkBlue}
            to={
              CVE_ID.test(filtersKeyword.trim())
                ? `/cves/${filtersKeyword.trim().toUpperCase()}`
                : `/cves?q=${encodeURIComponent(filtersKeyword.trim())}`
            }
          >
            {CVE_ID.test(filtersKeyword.trim())
              ? `Open ${filtersKeyword.trim().toUpperCase()}`
              : "CVEs"}
          </Link>
          {" · "}
          <Link
            as={RouterLink}
            color={linkBlue}
            to={`/packages?q=${encodeURIComponent(filtersKeyword.trim())}`}
          >
            Packages
          </Link>
          {ADVISORY_ID.test(filtersKeyword.trim()) && (
            <>
              {" · "}
              <Link
                as={RouterLink}
                color={linkBlue}
                to={`/${filtersKeyword.trim().toUpperCase()}`}
              >
                Open {filtersKeyword.trim().toUpperCase()}
              </Link>
            </>
          )}
        </Text>
      )}
      <HStack my={4} justifyContent="space-between" flexWrap="wrap">
        <Text fontStyle="italic" fontSize="xs">
          Last updated{" "}
          {lastUpdated ? new Date(lastUpdated).toLocaleString() : "never"}
        </Text>
        <HStack>
          <Text fontSize="xs">
            Displaying {(page * pageSize + 1).toLocaleString()}-
            {Math.min(total, page * pageSize + pageSize).toLocaleString()} of{" "}
            {total.toLocaleString()}
          </Text>
          <ButtonGroup
            size="xs"
            isAttached
            alignItems="stretch"
            colorScheme={pagerButtonScheme}
          >
            <IconButton
              aria-label="First Page"
              icon={<ArrowLeftIcon fontSize="8px" />}
              isDisabled={page <= 0}
              onClick={() => setPage(0)}
            />
            <IconButton
              aria-label="Previous Page"
              icon={<MinusIcon fontSize="8px" />}
              isDisabled={page <= 0}
              onClick={() => setPage((old) => old - 1)}
            />
            <Text
              fontSize="xs"
              borderColor="gray.200"
              backgroundColor={tableBg}
              lineHeight="24px"
              px={2}
            >
              {(page + 1).toLocaleString()} / {(lastPage + 1).toLocaleString()}
            </Text>
            <IconButton
              aria-label="Next Page"
              icon={<AddIcon fontSize="8px" />}
              isDisabled={page >= lastPage}
              onClick={() => setPage((old) => old + 1)}
            />
            <IconButton
              aria-label="Last Page"
              icon={<ArrowRightIcon fontSize="8px" />}
              isDisabled={page >= lastPage}
              onClick={() => setPage(lastPage)}
            />
          </ButtonGroup>
        </HStack>
      </HStack>
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
        <Box backgroundColor={tableBg} boxShadow="base">
          <TableContainer>
            <Table size="sm" variant="striped">
              <Thead>
                <Tr>
                  <Th {...stickyProps} width="36px" />
                  <Th {...stickyProps}>Advisory</Th>
                  <Th {...stickyProps}>Synopsis</Th>
                  <Th {...stickyProps}>Type / Severity</Th>
                  <Th {...stickyProps}>Products</Th>
                  <Th {...stickyProps}>Issue Date</Th>
                </Tr>
              </Thead>
              <Tbody>
                {!advisories?.length && (
                  <Tr>
                    <Td colSpan={6} textAlign="center">
                      <Text>No rows found</Text>
                    </Td>
                  </Tr>
                )}
                {advisories?.map((a) => (
                  <Tr key={a.name}>
                    <Td textAlign="center" pr={0}>
                      {severityToBadge(a.severity, a.type)}
                    </Td>
                    <Td>
                      <Link
                        as={RouterLink}
                        to={`/${a.name}`}
                        color={linkBlue}
                        _visited={{ color: linkPurple }}
                      >
                        {a.name}
                      </Link>
                    </Td>
                    <Td>
                      <Link
                        as={RouterLink}
                        to={`/${a.name}`}
                        color={linkBlue}
                        _visited={{ color: linkPurple }}
                      >
                        {a.synopsis?.replace(
                          /^(Critical|Important|Moderate|Low): /,
                          ""
                        )}
                      </Link>
                    </Td>
                    <Td>
                      {typeToText(a.type)}
                      {a.type === "TYPE_SECURITY"
                        ? ` / ${severityToText(a.severity)}`
                        : ""}
                    </Td>
                    <Td>{a.affectedProducts?.join(", ")}</Td>
                    <Td>
                      {a.publishedAt
                        ? Intl.DateTimeFormat(undefined, {
                            day: "2-digit",
                            month: "short",
                            year: "numeric",
                          }).format(new Date(a.publishedAt))
                        : ""}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </TableContainer>
        </Box>
      )}
      <HStack justifyContent="flex-end" mt={4}>
        <Text as="label" htmlFor="row-count" fontSize="sm">
          Rows per page:
        </Text>
        <Select
          id="row-count"
          name="row-count"
          variant="filled"
          backgroundColor={inputBackground}
          width="100px"
          size="sm"
          value={pageSize}
          onChange={(e) => {
            setPage(0);
            setPageSize(Number(e.currentTarget.value));
          }}
        >
          {[10, 25, 50, 100].map((count) => (
            <option key={count} value={count}>
              {count.toLocaleString()}
            </option>
          ))}
        </Select>
      </HStack>
    </Box>
  );
};
