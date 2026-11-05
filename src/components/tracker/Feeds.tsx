import { Box, Code, Heading, Link, ListItem, Text, UnorderedList } from "@chakra-ui/react";
import { useEffect } from "react";
import { Link as RouterLink } from "react-router-dom";

export function FeedsPage() {
  useEffect(() => {
    document.title = "Data feeds";
  }, []);

  return (
    <Box p={4} maxW="800px">
      <Heading size="md">Data feeds and API</Heading>
      <Text mt={1} fontSize="sm">
        Read-only feeds for the same Rocky Linux errata shown on this site. The site label Fix
        listed in advisory means a Rocky advisory names a fixed source build. It is not an
        independently verified RPM. Exports still use the stored status Patch available, along with
        In research, Not shipped, and not_affected. Not affected is a separate stored status. Not
        shipped is not that status.
      </Text>
      <Heading size="sm" mt={4} id="mcp">
        MCP
      </Heading>
      <Text mt={2} fontSize="sm">
        Anonymous, read-only Streamable HTTP. 100 requests per minute per IP. There is no
        subscription or notification tool.
      </Text>
      <Text mt={2} fontFamily="mono" fontSize="sm">
        https://errata.research.atomicorp.com/mcp
      </Text>
      <Text mt={3} fontSize="sm" fontWeight="600">
        Cursor
      </Text>
      <Code display="block" whiteSpace="pre" p={3} mt={1} fontSize="xs">{`{
  "mcpServers": {
    "rocky-errata": {
      "type": "streamableHttp",
      "url": "https://errata.research.atomicorp.com/mcp"
    }
  }
}`}</Code>
      <Text mt={3} fontSize="sm" fontWeight="600">
        Claude Code
      </Text>
      <Code display="block" whiteSpace="pre" p={3} mt={1} fontSize="xs">
        claude mcp add --transport http rocky-errata https://errata.research.atomicorp.com/mcp
      </Code>
      <Text mt={3} fontSize="sm" fontWeight="600">
        Claude Desktop
      </Text>
      <Code display="block" whiteSpace="pre" p={3} mt={1} fontSize="xs">{`{
  "mcpServers": {
    "rocky-errata": {
      "command": "npx",
      "args": ["mcp-remote", "https://errata.research.atomicorp.com/mcp"]
    }
  }
}`}</Code>
      <Text mt={3} fontSize="sm">
        Tools: search_cves, get_cve_context, list_products, list_component_versions, list_fixes,
        list_fixes_products. Example: “Which critical CVEs have a patch for Rocky Linux 9?”
      </Text>
      <Heading size="sm" mt={6}>
        CVE tracker
      </Heading>
      <UnorderedList mt={2}>
        <ListItem>
          <Link href="/api/v3/tracker/cves">JSON list</Link>,{" "}
          <Link href="/api/v3/tracker/cves.csv">CSV</Link>,{" "}
          <Link href="/api/v3/tracker/cves.rss">RSS</Link>. Same filters as the vulnerability page
          (q, product, severity, status, date_after, date_before). Add{" "}
          <Text as="span" fontFamily="mono">
            view=cves
          </Text>{" "}
          for one row per CVE; the default export is still one row per CVE, source package, and
          release. CSV and JSON stop at 10,000 rows and set X-Truncated when more exist. RSS is the
          50 newest rows.
        </ListItem>
        <ListItem>
          One CVE: <Text as="span" fontFamily="mono">/api/v3/tracker/cves/CVE-2022-1529</Text>
        </ListItem>
      </UnorderedList>
      <Heading size="sm" mt={6}>
        Advisories
      </Heading>
      <UnorderedList mt={2}>
        <ListItem>
          <Link href="/api/v3/tracker/fixes">JSON</Link>,{" "}
          <Link href="/api/v3/tracker/fixes.csv">CSV</Link>,{" "}
          <Link href="/api/v3/tracker/fixes.rss">RSS</Link>, plus the existing{" "}
          <Link href="/api/v2/advisories:rss">advisory RSS</Link>.
        </ListItem>
        <ListItem>
          CSAF advisory: <Text as="span" fontFamily="mono">/api/v3/csaf/advisories/RLSA-…</Text>
        </ListItem>
        <ListItem>
          CSAF VEX for one CVE: <Text as="span" fontFamily="mono">/api/v3/csaf/vex/CVE-…</Text>
        </ListItem>
        <ListItem>
          OVAL: <Link href="/api/v3/oval/rocky-linux/8">8</Link>,{" "}
          <Link href="/api/v3/oval/rocky-linux/9">9</Link>,{" "}
          <Link href="/api/v3/oval/rocky-linux/10">10</Link>
        </ListItem>
      </UnorderedList>
      <Heading size="sm" mt={6}>
        Source packages
      </Heading>
      <Text mt={2}>
        <Link href="/api/v3/tracker/technologies">/api/v3/tracker/technologies</Link> lists source
        package and latest version per release. It does not list binary RPMs. The same catalog is
        browsable at{" "}
        <Link as={RouterLink} to="/packages">
          /packages
        </Link>{" "}
        (secondary page; not in the header).
      </Text>
      <Heading size="sm" mt={6}>
        Not provided here
      </Heading>
      <UnorderedList mt={2}>
        <ListItem>No email subscription or notification product list.</ListItem>
        <ListItem>No sitemap yet.</ListItem>
        <ListItem>No claim of a full OSV corpus on this host.</ListItem>
        <ListItem>Update frequency is the research catalog schedule, not a per-row SLA.</ListItem>
      </UnorderedList>
    </Box>
  );
}
