import { MoonIcon, SunIcon } from "@chakra-ui/icons";
import {
  Box,
  HStack,
  Text,
  Link as ChakraLink,
  useColorMode,
  IconButton,
  useColorModeValue,
  DarkMode,
} from "@chakra-ui/react";
import { Route, Routes, Link } from "react-router-dom";

import { COLOR_RESF_BLUE, COLOR_RESF_GREEN } from "../styles";
import { getRSSUrl } from "../api/client";
import { RESFLogo } from "./RESFLogo";
import { Overview } from "./Overview";
import { ShowErrata } from "./ShowErrata";

export const Root = () => {
  const { colorMode, toggleColorMode } = useColorMode();

  const SwitchIcon = useColorModeValue(MoonIcon, SunIcon);
  const bodyBg = useColorModeValue("gray.100", "gray.900");

  return (
    <Box
      display="flex"
      width="100%"
      minHeight="100vh"
      flexDirection="column"
      alignItems="stretch"
    >
      <Box
        as="header"
        background={`linear-gradient(to bottom right, ${COLOR_RESF_GREEN}, ${COLOR_RESF_BLUE})`}
        display="flex"
        flexDirection="row"
        alignItems="center"
        justifyContent="space-between"
        py="1"
        px={4}
      >
        <Link to="/" className="no-underline text-white">
          <HStack flexGrow={1} height="90%" spacing="2">
            <RESFLogo className="fill-current text-white" />
            <Text
              as="h1"
              borderLeft="1px solid"
              pl="2"
              lineHeight="30px"
              fontSize="xl"
              fontWeight="300"
              color="white"
              whiteSpace="nowrap"
            >
              Product Errata
            </Text>
          </HStack>
        </Link>
        <DarkMode>
          <IconButton
            size="md"
            fontSize="lg"
            aria-label={`Switch to ${
              colorMode === "light" ? "dark" : "light"
            } mode`}
            variant="ghost"
            onClick={toggleColorMode}
            icon={<SwitchIcon />}
          />
        </DarkMode>
      </Box>
      <Box as="main" flexGrow={1} overflow="auto" background={bodyBg}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/:id" element={<ShowErrata />} />
        </Routes>
      </Box>
      <Box
        as="footer"
        px="4"
        background={`linear-gradient(to top left, ${COLOR_RESF_GREEN}, ${COLOR_RESF_BLUE})`}
        color="white"
        display="flex"
        height="50px"
      >
        <ChakraLink
          href={getRSSUrl()}
          isExternal
          display="flex"
          alignItems="center"
          my="auto"
        >
          <Box
            as="svg"
            viewBox="0 0 24 24"
            width="18px"
            height="18px"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            display="block"
            mr={1.5}
          >
            <path d="M4 11a9 9 0 019 9M4 4a16 16 0 0116 16" />
            <circle cx="5" cy="19" r="1" />
          </Box>
          <span>RSS</span>
        </ChakraLink>
        <Text fontSize="xs" my="auto" ml="auto" textAlign="right">
          Advisory content derived from Red Hat, used under{" "}
          <ChakraLink
            href="https://creativecommons.org/licenses/by/4.0/"
            isExternal
            textDecoration="underline"
          >
            CC BY 4.0
          </ChakraLink>
          , with modifications.
        </Text>
      </Box>
    </Box>
  );
};
