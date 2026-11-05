import {
  Box,
  HStack,
  IconButton,
  ListItem,
  Popover,
  PopoverArrow,
  PopoverBody,
  PopoverCloseButton,
  PopoverContent,
  PopoverHeader,
  PopoverTrigger,
  Text,
  UnorderedList,
  useColorModeValue,
  type TextProps,
} from "@chakra-ui/react";

import { METRIC_HELP, type MetricHelpId } from "../lib/metricHelp";

function InfoGlyph() {
  return (
    <Box
      as="span"
      display="inline-flex"
      alignItems="center"
      justifyContent="center"
      w="14px"
      h="14px"
      borderRadius="full"
      borderWidth="1.5px"
      borderColor="currentColor"
      fontSize="9px"
      fontWeight="700"
      lineHeight="1"
      fontStyle="normal"
      textTransform="none"
    >
      i
    </Box>
  );
}

/** Compact (i) control with in-app explanation popover (no external link). */
export function MetricInfoHint({
  id,
  note,
  "aria-label": ariaLabel,
}: {
  id: MetricHelpId;
  note?: string;
  "aria-label"?: string;
}) {
  const help = METRIC_HELP[id];
  const footnote = note ?? help.note;
  const muted = useColorModeValue("gray.500", "gray.400");
  const bodyMuted = useColorModeValue("gray.600", "gray.300");

  return (
    <Popover placement="bottom-start" isLazy gutter={8}>
      <PopoverTrigger>
        <IconButton
          aria-label={ariaLabel ?? `About ${help.title}`}
          icon={<InfoGlyph />}
          size="xs"
          variant="ghost"
          color={muted}
          minW="18px"
          h="18px"
          p={0}
          borderRadius="full"
          _hover={{ color: "blue.400", bg: "transparent" }}
          onClick={(e) => e.stopPropagation()}
        />
      </PopoverTrigger>
      <PopoverContent
        maxW="360px"
        w="min(360px, 92vw)"
        fontSize="sm"
        textTransform="none"
        letterSpacing="normal"
        zIndex={1400}
      >
        <PopoverArrow />
        <PopoverCloseButton />
        <PopoverHeader fontWeight="semibold" borderBottomWidth="1px" pr={8}>
          {help.title}
        </PopoverHeader>
        <PopoverBody>
          <Text mb={2} color={bodyMuted}>
            {help.summary}
          </Text>
          <UnorderedList spacing={1.5} pl={1} mb={footnote ? 2 : 0}>
            {help.bullets.map((b) => (
              <ListItem key={b} color={bodyMuted} fontSize="xs">
                {b}
              </ListItem>
            ))}
          </UnorderedList>
          {footnote && (
            <Text fontSize="xs" color={muted} fontStyle="italic">
              {footnote}
            </Text>
          )}
        </PopoverBody>
      </PopoverContent>
    </Popover>
  );
}

export function MetricLabelWithInfo({
  label,
  helpId,
  mb,
  ...textProps
}: {
  label: string;
  helpId: MetricHelpId;
  mb?: TextProps["mb"];
} & TextProps) {
  return (
    <HStack spacing={1} align="center" display="inline-flex" mb={mb}>
      <Text as="span" {...textProps}>
        {label}
      </Text>
      <MetricInfoHint id={helpId} />
    </HStack>
  );
}
