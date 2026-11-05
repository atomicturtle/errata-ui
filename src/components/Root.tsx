import { MoonIcon, SunIcon } from "@chakra-ui/icons";
import {
  Box,
  Button,
  HStack,
  Text,
  Link as ChakraLink,
  useColorMode,
  IconButton,
  useColorModeValue,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, Link, useLocation, useSearchParams } from "react-router-dom";

import { COLOR_RESF_BLUE, COLOR_RESF_GREEN } from "../styles";
import { getRSSUrl } from "../api/client";
import { RESFLogo } from "./RESFLogo";
import { Overview } from "./Overview";
import { ShowErrata } from "./ShowErrata";
import { CveDetailPage } from "./tracker/CveDetail";
import { CveList } from "./tracker/CveList";
import { FeedsPage } from "./tracker/Feeds";
import { FixesPage } from "./tracker/Fixes";
import { TechnologiesPage } from "./tracker/Technologies";

function SearchRedirect() {
  const [params] = useSearchParams();
  const q = params.get("q");
  return <Navigate to={q ? `/?q=${encodeURIComponent(q)}` : "/"} replace />;
}

function AdvisoriesRedirect() {
  const location = useLocation();
  return <Navigate to={{ pathname: "/", search: location.search }} replace />;
}

type ThemePref = "light" | "dark" | "system";
const THEME_KEY = "rocky-theme";

function ThemeSwitch() {
  const { setColorMode } = useColorMode();
  const [pref, setPref] = useState<ThemePref>(() => {
    const stored = window.localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
    return "system";
  });

  useEffect(() => {
    if (pref === "system") {
      const media = window.matchMedia("(prefers-color-scheme: dark)");
      const apply = () => setColorMode(media.matches ? "dark" : "light");
      apply();
      media.addEventListener("change", apply);
      return () => media.removeEventListener("change", apply);
    }
    setColorMode(pref);
    return undefined;
  }, [pref, setColorMode]);

  function choose(next: ThemePref) {
    window.localStorage.setItem(THEME_KEY, next);
    setPref(next);
  }

  return (
    <HStack spacing={1}>
      <IconButton
        aria-label="Light theme"
        title="Light theme"
        aria-pressed={pref === "light"}
        size="sm"
        color="white"
        variant={pref === "light" ? "solid" : "ghost"}
        icon={<SunIcon />}
        onClick={() => choose("light")}
      />
      <IconButton
        aria-label="Dark theme"
        title="Dark theme"
        aria-pressed={pref === "dark"}
        size="sm"
        color="white"
        variant={pref === "dark" ? "solid" : "ghost"}
        icon={<MoonIcon />}
        onClick={() => choose("dark")}
      />
      <Button
        aria-label="Match this device's light or dark appearance"
        title="Match this device's light or dark appearance"
        aria-pressed={pref === "system"}
        size="sm"
        color="white"
        variant={pref === "system" ? "solid" : "ghost"}
        onClick={() => choose("system")}
      >
        System
      </Button>
    </HStack>
  );
}

function SectionLink({
  to,
  children,
  end = false,
  active,
}: {
  to: string;
  children: string;
  end?: boolean;
  active?: boolean;
}) {
  return (
    <NavLink to={to} end={end}>
      {({ isActive }) => {
        const on = active ?? isActive;
        return (
          <Text
            as="span"
            px={2}
            py={1}
            fontWeight={on ? "600" : "400"}
            borderBottom={on ? "2px solid" : "2px solid transparent"}
            borderColor={on ? COLOR_RESF_GREEN : "transparent"}
          >
            {children}
          </Text>
        );
      }}
    </NavLink>
  );
}

export const Root = () => {
  const bodyBg = useColorModeValue("gray.100", "gray.900");
  const navBg = useColorModeValue("white", "gray.800");
  const { pathname } = useLocation();
  const section = pathname.startsWith("/cves")
    ? "cves"
    : pathname.startsWith("/feeds")
      ? "feeds"
      : "advisories";

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
            <Box lineHeight="1.1">
              <Text as="h1" fontSize="md" fontWeight="500" color="white" whiteSpace="nowrap">
                Rocky Linux Errata
              </Text>
              <Text fontSize="xs" color="whiteAlpha.800" display={{ base: "none", md: "block" }}>
                Security advisories, bug fixes, and enhancements
              </Text>
            </Box>
          </HStack>
        </Link>
        <ThemeSwitch />
      </Box>
      <HStack as="nav" aria-label="Sections" px={4} py={2} bg={navBg} spacing={4}>
        <SectionLink to="/" end active={section === "advisories"}>
          Advisories
        </SectionLink>
        <SectionLink to="/cves" active={section === "cves"}>
          CVEs
        </SectionLink>
        <SectionLink to="/feeds" active={section === "feeds"}>
          Data Feeds / API
        </SectionLink>
      </HStack>
      <Box as="main" flexGrow={1} overflow="auto" background={bodyBg}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/advisories" element={<AdvisoriesRedirect />} />
          <Route path="/cves" element={<CveList />} />
          <Route path="/cves/:cveId" element={<CveDetailPage />} />
          <Route path="/fixes" element={<FixesPage />} />
          <Route path="/packages" element={<TechnologiesPage />} />
          <Route path="/feeds" element={<FeedsPage />} />
          <Route path="/about" element={<Navigate to="/" replace />} />
          <Route path="/search" element={<SearchRedirect />} />
          <Route path="/technologies" element={<Navigate to="/packages" replace />} />
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
