import { Box, HStack, Text, Tooltip, useColorModeValue } from "@chakra-ui/react";
import type { ReactNode } from "react";

import {
  cvssScoreToSeverity,
  exploitMaturityRank,
  parseCvss3Metrics,
  parseScore,
  severityColor,
  severityGaugePercent,
  type CvssSeverityLabel,
  type NvdCve,
} from "../lib/nvd";
import { MetricLabelWithInfo } from "./MetricInfoHint";

const SEV_BG: Record<CvssSeverityLabel, string> = {
  NONE: "rgba(100, 116, 139, 0.65)",
  LOW: "rgba(34, 197, 94, 0.75)",
  MEDIUM: "rgba(245, 158, 11, 0.8)",
  HIGH: "rgba(239, 68, 68, 0.85)",
  CRITICAL: "rgba(145, 35, 62, 0.95)",
};

function IconBox({
  children,
  color,
}: {
  children: ReactNode;
  color: string;
}) {
  return (
    <Box
      w="36px"
      h="36px"
      borderRadius="md"
      display="flex"
      alignItems="center"
      justifyContent="center"
      bg={`${color}22`}
      color={color}
      flexShrink={0}
    >
      {children}
    </Box>
  );
}

function GlobeIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" w="20px" h="20px" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" />
    </Box>
  );
}

function GaugeIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" w="20px" h="20px" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M5 19a9 9 0 1114 0" />
      <path d="M12 16l4-6" />
      <circle cx="12" cy="16" r="1.5" fill="currentColor" />
    </Box>
  );
}

function UserIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" w="20px" h="20px" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="8" r="3.5" />
      <path d="M5 19a7 7 0 0114 0" />
    </Box>
  );
}

function NoInteractIcon() {
  return (
    <Box as="svg" viewBox="0 0 24 24" w="20px" h="20px" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="9" />
      <path d="M6 6l12 12" />
    </Box>
  );
}

function ShieldMini() {
  return (
    <Box as="svg" viewBox="0 0 24 24" w="22px" h="22px" fill="currentColor">
      <path d="M12 2L4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z" />
    </Box>
  );
}

/** Compact CVSS score card with mini severity gauge. */
export function CvssScoreCard({
  label,
  score,
}: {
  label: string;
  score: number | null;
}) {
  const border = useColorModeValue("gray.200", "gray.600");
  const bg = useColorModeValue("gray.50", "gray.900");
  const muted = useColorModeValue("gray.500", "gray.400");
  const sev = cvssScoreToSeverity(score);
  const pct = severityGaugePercent(score);

  return (
    <Box
      borderWidth="1px"
      borderColor={border}
      borderRadius="md"
      bg={bg}
      px={3}
      py={2.5}
      minW="120px"
      flex="1"
    >
      <Text fontSize="2xs" textTransform="uppercase" color={muted} mb={1}>
        {label}
      </Text>
      {score === null ? (
        <Text fontSize="sm" color={muted}>
          —
        </Text>
      ) : (
        <>
          <HStack align="baseline" spacing={2}>
            <Text fontSize="2xl" fontWeight="800" color={severityColor(sev)} lineHeight="1">
              {score.toFixed(1)}
            </Text>
            <Text fontSize="xs" fontWeight="bold" color={severityColor(sev)}>
              {sev}
            </Text>
          </HStack>
          <Box
            mt={2}
            h="6px"
            borderRadius="full"
            overflow="hidden"
            background="linear-gradient(90deg, #22c55e 0%, #84cc16 25%, #eab308 50%, #f97316 75%, #ef4444 100%)"
            position="relative"
          >
            <Box
              position="absolute"
              top="-2px"
              left={`calc(${pct}% - 4px)`}
              w="8px"
              h="10px"
              borderRadius="sm"
              bg="white"
              border="1px solid"
              borderColor="gray.700"
            />
          </Box>
        </>
      )}
    </Box>
  );
}

export function EpssCard({ score }: { score?: string | null }) {
  const border = useColorModeValue("gray.200", "gray.600");
  const bg = useColorModeValue("gray.50", "gray.900");
  const muted = useColorModeValue("gray.500", "gray.400");
  const n = score != null && score !== "" ? Number(score) : null;
  const pct = n !== null && Number.isFinite(n) ? Math.min(100, Math.max(0, n * 100)) : null;

  return (
    <Box
      borderWidth="1px"
      borderColor={border}
      borderRadius="md"
      bg={bg}
      px={3}
      py={2.5}
      minW="110px"
    >
      <MetricLabelWithInfo
        label="EPSS"
        helpId="epss"
        fontSize="2xs"
        textTransform="uppercase"
        color={muted}
        mb={1}
      />
      {pct === null ? (
        <Text fontSize="sm" color={muted}>
          —
        </Text>
      ) : (
        <>
          <Text fontSize="lg" fontWeight="800" color="blue.300">
            {pct.toFixed(2)}%
          </Text>
          <Box mt={2} h="6px" borderRadius="full" bg="whiteAlpha.200" overflow="hidden">
            <Box h="100%" w={`${Math.max(pct, 1)}%`} bg="blue.400" borderRadius="full" />
          </Box>
        </>
      )}
    </Box>
  );
}

export function MetricChip({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string;
  icon: ReactNode;
  color: string;
}) {
  const border = useColorModeValue("gray.200", "gray.600");
  const bg = useColorModeValue("gray.50", "gray.900");
  const muted = useColorModeValue("gray.500", "gray.400");

  return (
    <HStack
      borderWidth="1px"
      borderColor={border}
      borderRadius="md"
      bg={bg}
      px={2.5}
      py={2}
      spacing={2.5}
      minW="130px"
    >
      <IconBox color={color}>{icon}</IconBox>
      <Box minW={0}>
        <Text fontSize="2xs" textTransform="uppercase" color={muted} noOfLines={1}>
          {label}
        </Text>
        <Text fontSize="sm" fontWeight="bold" textTransform="uppercase" noOfLines={1}>
          {value}
        </Text>
      </Box>
    </HStack>
  );
}

export function ExploitMaturityChip({ label }: { label?: string | null }) {
  const border = useColorModeValue("gray.200", "gray.600");
  const bg = useColorModeValue("gray.50", "gray.900");
  const muted = useColorModeValue("gray.500", "gray.400");
  const filled = "orange.400";
  const empty = useColorModeValue("gray.300", "gray.600");
  const rank = exploitMaturityRank(label);

  return (
    <Box
      borderWidth="1px"
      borderColor={border}
      borderRadius="md"
      bg={bg}
      px={3}
      py={2}
      minW="150px"
    >
      <MetricLabelWithInfo
        label="Exploit Maturity"
        helpId="exploit_maturity"
        fontSize="2xs"
        textTransform="uppercase"
        color={muted}
        mb={1}
      />
      <Text fontSize="sm" fontWeight="bold" textTransform="uppercase" mb={1.5}>
        {label || "—"}
      </Text>
      <HStack spacing={1.5}>
        {[1, 2, 3, 4].map((i) => (
          <Box
            key={i}
            w="10px"
            h="10px"
            borderRadius="full"
            bg={label && i <= Math.min(rank, 4) ? filled : empty}
          />
        ))}
      </HStack>
      {label && rank >= 2 && (
        <Text fontSize="2xs" color="orange.300" mt={1}>
          Exploit Available
        </Text>
      )}
    </Box>
  );
}

/** Full hero metrics strip matching the errata mockup. */
export function ErrataMetricsStrip({ primary }: { primary?: NvdCve }) {
  const border = useColorModeValue("gray.200", "gray.600");
  const bg = useColorModeValue("gray.50", "gray.900");
  const muted = useColorModeValue("gray.500", "gray.400");
  const v3 = parseScore(primary?.cvss_v3_score);
  const v4 = parseScore(primary?.cvss_v4_score);
  const metrics = parseCvss3Metrics(primary?.cvss_v3_vector);
  const sev = cvssScoreToSeverity(v3);
  const showV4 = v4 !== null;

  return (
    <HStack spacing={3} align="stretch" flexWrap="wrap">
      <CvssScoreCard label="CVSS v3.1 Base Score" score={v3} />
      {showV4 && <CvssScoreCard label="CVSS v4.0 Base Score" score={v4} />}
      <Box borderWidth="1px" borderColor={border} borderRadius="md" bg={bg} px={3} py={2.5} minW="120px">
        <Text fontSize="2xs" textTransform="uppercase" color={muted} mb={1}>
          Severity
        </Text>
        <Text fontSize="lg" fontWeight="800" color={severityColor(sev)}>
          {sev === "NONE" ? "—" : sev}
        </Text>
        {v3 !== null && (
          <Text fontSize="2xs" color="gray.500">
            (CVSS v3.1)
          </Text>
        )}
      </Box>
      <EpssCard score={primary?.epss_score} />
      <MetricChip
        label="Attack Vector"
        value={metrics["Attack Vector"] || "—"}
        icon={<GlobeIcon />}
        color="#38bdf8"
      />
      <MetricChip
        label="Attack Complexity"
        value={metrics["Attack Complexity"] || "—"}
        icon={<GaugeIcon />}
        color="#a78bfa"
      />
      <MetricChip
        label="Privileges Required"
        value={metrics["Privileges Required"] || "—"}
        icon={<UserIcon />}
        color="#34d399"
      />
      <MetricChip
        label="User Interaction"
        value={metrics["User Interaction"] || "—"}
        icon={<NoInteractIcon />}
        color="#f472b6"
      />
      <ExploitMaturityChip label={primary?.exploit_maturity} />
    </HStack>
  );
}

export function ErrataTitleShield() {
  return (
    <Box color="#10B981" flexShrink={0} mt={1}>
      <ShieldMini />
    </Box>
  );
}

/** AWP-style CVSS numeric badge (colored pill). */
export function CvssBadge({
  score,
  severity,
}: {
  score: number | null;
  severity: CvssSeverityLabel;
}) {
  if (score === null) {
    return (
      <Text fontSize="sm" color="gray.500">
        —
      </Text>
    );
  }
  return (
    <Box
      as="span"
      display="inline-flex"
      alignItems="center"
      justifyContent="center"
      minW="44px"
      h="28px"
      px={2}
      borderRadius="md"
      bg={SEV_BG[severity]}
      color="white"
      fontSize="md"
      fontWeight="800"
      letterSpacing="tight"
      lineHeight="1"
    >
      {score.toFixed(1)}
    </Box>
  );
}

/** AWP-style severity pill with warning / down / check icons. */
export function SeverityPill({ severity }: { severity: CvssSeverityLabel }) {
  if (severity === "NONE") {
    return (
      <Text fontSize="sm" color="gray.500">
        —
      </Text>
    );
  }

  const label = severity === "MEDIUM" ? "moderate" : severity.toLowerCase();

  let icon: ReactNode;
  if (severity === "CRITICAL" || severity === "HIGH") {
    icon = (
      <Text as="span" color="#ef4444" fontSize="lg" fontWeight="bold" lineHeight="1">
        ⚠
      </Text>
    );
  } else if (severity === "MEDIUM") {
    icon = (
      <Box
        display="inline-flex"
        alignItems="center"
        justifyContent="center"
        w="22px"
        h="22px"
        bg="#ca8a04"
        color="white"
        fontSize="sm"
        fontWeight="bold"
        borderRadius="sm"
      >
        ↓
      </Box>
    );
  } else {
    icon = (
      <Box
        display="inline-flex"
        alignItems="center"
        justifyContent="center"
        w="22px"
        h="22px"
        bg="#16a34a"
        color="white"
        fontSize="sm"
        fontWeight="bold"
        borderRadius="full"
      >
        ✓
      </Box>
    );
  }

  return (
    <HStack
      spacing={2}
      px={2}
      py={1}
      borderRadius="md"
      bg={SEV_BG[severity]}
      color="white"
      w="fit-content"
      minW="92px"
      justify="center"
    >
      {icon}
      <Text fontSize="sm" fontWeight="bold" textTransform="capitalize">
        {label}
      </Text>
    </HStack>
  );
}

/** Attack-vector badge matching AWP `attack_vector_badge`. */
export function AttackVectorBadge({ vector }: { vector?: string | null }) {
  const bg = useColorModeValue("blackAlpha.100", "whiteAlpha.100");
  const metrics = parseCvss3Metrics(vector);
  const av = metrics["Attack Vector"];
  if (!av || av === "—") return null;

  const icon =
    av === "Network" ? "◉" : av === "Adjacent" ? "⊕" : av === "Local" || av === "Physical" ? "⊙" : "•";

  const color =
    av === "Network"
      ? "#ef4444"
      : av === "Adjacent"
        ? "#fb923c"
        : av === "Local"
          ? "#facc15"
          : av === "Physical"
            ? "#38bdf8"
            : "gray.400";

  return (
    <HStack
      spacing={1.5}
      px={2}
      py={1}
      borderRadius="md"
      bg={bg}
      w="fit-content"
      borderWidth="1px"
      borderColor="whiteAlpha.200"
    >
      <Text as="span" color={color} fontSize="sm" lineHeight="1">
        {icon}
      </Text>
      <Text fontSize="sm" fontWeight="semibold">
        {av}
      </Text>
    </HStack>
  );
}

/** Exploit maturity label + dots (legacy compact). */
export function ExploitMaturityBadge({ label }: { label?: string | null }) {
  const rank = exploitMaturityRank(label);
  const filled = useColorModeValue("orange.400", "orange.400");
  const empty = useColorModeValue("gray.300", "gray.600");
  const bg = useColorModeValue("blackAlpha.100", "whiteAlpha.100");

  if (!label) {
    return (
      <Text fontSize="sm" color="gray.500">
        —
      </Text>
    );
  }

  return (
    <Box>
      <HStack
        spacing={2}
        px={2}
        py={1}
        borderRadius="md"
        bg={bg}
        w="fit-content"
        borderWidth="1px"
        borderColor="whiteAlpha.200"
        mb={1.5}
      >
        <Text fontSize="sm" fontWeight="semibold">
          {label}
        </Text>
      </HStack>
      <HStack spacing={1}>
        {[1, 2, 3, 4].map((i) => (
          <Box
            key={i}
            w="8px"
            h="8px"
            borderRadius="full"
            bg={i <= Math.min(rank, 4) ? filled : empty}
          />
        ))}
      </HStack>
    </Box>
  );
}

export function EpssMiniBar({ score }: { score?: string | null }) {
  const n = score != null && score !== "" ? Number(score) : null;
  if (n === null || !Number.isFinite(n)) {
    return (
      <Text fontSize="xs" color="gray.500">
        —
      </Text>
    );
  }
  const pct = Math.min(100, Math.max(0, n * 100));
  return (
    <Tooltip label={`${pct.toFixed(2)}%`}>
      <HStack spacing={2} minW="80px">
        <Box flex="1" h="6px" borderRadius="full" bg="whiteAlpha.200" overflow="hidden">
          <Box h="100%" w={`${Math.max(pct, 2)}%`} bg="blue.400" />
        </Box>
        <Text fontSize="xs" fontWeight="semibold" minW="42px">
          {pct.toFixed(1)}%
        </Text>
      </HStack>
    </Tooltip>
  );
}
