import { ChevronDownIcon, DownloadIcon } from "@chakra-ui/icons";
import {
  Box,
  Button,
  Checkbox,
  Collapse,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Link,
  Menu,
  MenuButton,
  MenuItem,
  MenuList,
  Popover,
  PopoverBody,
  PopoverContent,
  PopoverTrigger,
  Select,
  Stack,
  Text,
  useColorModeValue,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";

import { exportUrl } from "../../api/tracker";
import { useDebouncedQuery, useTrackerParams } from "./params";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Awaiting analysis"];
const STATUSES = [
  { value: "Patch available", label: "Fix listed in advisory" },
  { value: "In research", label: "In research" },
  { value: "Not shipped", label: "Not shipped" },
  { value: "Not affected", label: "Not affected" },
];

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "red",
  High: "orange",
  Medium: "yellow",
  Low: "green",
  "Awaiting analysis": "gray",
};

export function severityColor(severity: string): string {
  return SEVERITY_COLOR[severity] ?? "gray";
}

export function fixStatusLabel(status: string): string {
  return STATUSES.find((item) => item.value === status)?.label ?? status;
}

export function TrackerFilters({
  products,
  exportPath,
  placeholder,
  showStatus = false,
  showType = false,
  showArch = false,
  showSeverity = true,
  showDates = true,
  dateLabel = "Published",
  advancedDates = false,
  compactExports = false,
  exportView = null,
}: {
  products: string[];
  exportPath: string;
  placeholder: string;
  showStatus?: boolean;
  showType?: boolean;
  showArch?: boolean;
  showSeverity?: boolean;
  showDates?: boolean;
  dateLabel?: string;
  advancedDates?: boolean;
  compactExports?: boolean;
  exportView?: string | null;
}) {
  const { params, update } = useTrackerParams();
  const { draft, setDraft } = useDebouncedQuery(params, update);
  const inputBackground = useColorModeValue("white", "gray.700");
  const selectedProducts = params.getAll("product");
  const selectedSeverities = params.getAll("severity");
  const datesActive = Boolean(params.get("date_after") || params.get("date_before"));
  const [advancedOpen, setAdvancedOpen] = useState(datesActive);
  const exportParams = new URLSearchParams(params);
  if (exportView) exportParams.set("view", exportView);

  useEffect(() => {
    if (datesActive) setAdvancedOpen(true);
  }, [datesActive]);

  function toggle(key: "product" | "severity", value: string, current: string[]) {
    const next = current.includes(value)
      ? current.filter((item) => item !== value)
      : [...current, value];
    update({ [key]: next });
  }

  return (
    <Stack spacing={3}>
      <Stack direction={{ base: "column", xl: "row" }} align={{ xl: "flex-end" }}>
        <FormControl>
          <FormLabel fontSize="sm">Search</FormLabel>
          <Input
            aria-label="Search"
            placeholder={placeholder}
            value={draft}
            background={inputBackground}
            onChange={(event) => setDraft(event.target.value)}
          />
        </FormControl>
        <FormControl maxW={{ xl: "240px" }}>
          <FormLabel fontSize="sm">Product</FormLabel>
          <Popover>
            <PopoverTrigger>
              <Button width="100%" justifyContent="space-between" variant="outline">
                {selectedProducts.length ? selectedProducts.join(", ") : "All"}
              </Button>
            </PopoverTrigger>
            <PopoverContent>
              <PopoverBody>
                <Stack>
                  {products.map((product) => (
                    <Checkbox
                      key={product}
                      isChecked={selectedProducts.includes(product)}
                      onChange={() => toggle("product", product, selectedProducts)}
                    >
                      {product}
                    </Checkbox>
                  ))}
                  {!products.length && <Text fontSize="sm">No products yet</Text>}
                </Stack>
              </PopoverBody>
            </PopoverContent>
          </Popover>
        </FormControl>
        {showStatus && (
          <FormControl maxW={{ xl: "240px" }}>
            <FormLabel fontSize="sm">Status</FormLabel>
            <Select
              aria-label="Status"
              background={inputBackground}
              value={params.get("status") ?? ""}
              onChange={(event) => update({ status: event.target.value || null })}
            >
              <option value="">All</option>
              {STATUSES.map((status) => (
                <option key={status.value} value={status.value}>
                  {status.label}
                </option>
              ))}
            </Select>
          </FormControl>
        )}
        {showType && (
          <FormControl maxW={{ xl: "180px" }}>
            <FormLabel fontSize="sm">Type</FormLabel>
            <Select
              aria-label="Type"
              background={inputBackground}
              value={params.get("type") ?? ""}
              onChange={(event) => update({ type: event.target.value || null })}
            >
              <option value="">All</option>
              <option value="security">Security</option>
              <option value="bugfix">Bug fix</option>
              <option value="enhancement">Enhancement</option>
            </Select>
          </FormControl>
        )}
        {showArch && (
          <FormControl maxW={{ xl: "140px" }}>
            <FormLabel fontSize="sm">Arch</FormLabel>
            <Input
              aria-label="Arch"
              placeholder="x86_64"
              background={inputBackground}
              value={params.get("arch") ?? ""}
              onChange={(event) => update({ arch: event.target.value || null })}
            />
          </FormControl>
        )}
        {showDates && !advancedDates && (
          <DateRange dateLabel={dateLabel} background={inputBackground} />
        )}
      </Stack>
      {showDates && advancedDates && (
        <Box>
          <Button
            size="sm"
            variant="outline"
            aria-expanded={advancedOpen}
            onClick={() => setAdvancedOpen((open) => !open)}
          >
            Advanced filters
          </Button>
          <Collapse in={advancedOpen}>
            <HStack mt={3} align="flex-end" flexWrap="wrap">
              <DateRange dateLabel={dateLabel} background={inputBackground} />
            </HStack>
          </Collapse>
        </Box>
      )}
      <HStack flexWrap="wrap">
        {showSeverity && (
          <Text
            fontSize="sm"
            title="For a patched row this is the Rocky advisory severity. Otherwise it is the CVSS band."
          >
            Severity
          </Text>
        )}
        {showSeverity &&
          SEVERITIES.map((severity) => {
            const on = selectedSeverities.includes(severity);
            return (
              <Button
                key={severity}
                size="sm"
                variant={on ? "solid" : "outline"}
                colorScheme={severityColor(severity)}
                aria-pressed={on}
                onClick={() => toggle("severity", severity, selectedSeverities)}
              >
                {severity}
              </Button>
            );
          })}
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            update({
              q: null,
              product: [],
              severity: [],
              status: null,
              type: null,
              arch: null,
              date_after: null,
              date_before: null,
            });
            setDraft("");
          }}
        >
          Clear
        </Button>
        {compactExports ? (
          <Menu>
            <MenuButton as={Button} size="sm" variant="outline" leftIcon={<DownloadIcon />} rightIcon={<ChevronDownIcon />}>
              Export
            </MenuButton>
            <MenuList>
              <MenuItem as={Link} href={exportUrl(`${exportPath}.csv`, exportParams)}>
                CSV
              </MenuItem>
              <MenuItem as={Link} href={exportUrl(`${exportPath}.json`, exportParams)}>
                JSON
              </MenuItem>
              <MenuItem as={Link} href={exportUrl(`${exportPath}.rss`, exportParams)} isExternal>
                RSS
              </MenuItem>
            </MenuList>
          </Menu>
        ) : (
          <>
            <Link href={exportUrl(`${exportPath}.csv`, exportParams)} display="inline-flex" alignItems="center">
              <DownloadIcon mr={1} /> CSV
            </Link>
            <Link href={exportUrl(`${exportPath}.json`, exportParams)} display="inline-flex" alignItems="center">
              <DownloadIcon mr={1} /> JSON
            </Link>
            <Link href={exportUrl(`${exportPath}.rss`, exportParams)} isExternal display="inline-flex" alignItems="center">
              RSS
            </Link>
          </>
        )}
      </HStack>
    </Stack>
  );
}

function DateRange({ dateLabel, background }: { dateLabel: string; background: string }) {
  const { params, update } = useTrackerParams();
  return (
    <>
      <FormControl maxW={{ xl: "180px" }}>
        <FormLabel fontSize="sm">{dateLabel} after</FormLabel>
        <Input
          aria-label={`${dateLabel} after`}
          type="date"
          background={background}
          value={params.get("date_after") ?? ""}
          onChange={(event) => update({ date_after: event.target.value || null })}
        />
      </FormControl>
      <FormControl maxW={{ xl: "180px" }}>
        <FormLabel fontSize="sm">{dateLabel} before</FormLabel>
        <Input
          aria-label={`${dateLabel} before`}
          type="date"
          background={background}
          value={params.get("date_before") ?? ""}
          onChange={(event) => update({ date_before: event.target.value || null })}
        />
      </FormControl>
    </>
  );
}
