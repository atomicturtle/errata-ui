import {
  Alert,
  AlertDescription,
  AlertIcon,
  AlertTitle,
  Box,
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  Heading,
  HStack,
  Link,
  ListItem,
  Spinner,
  Tab,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  Text,
  UnorderedList,
  useColorModeValue,
  VStack,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { useParams, Link as RouterLink } from "react-router-dom";

import { getAdvisory } from "../api/client";
import type { V2Advisory } from "../api/types";
import { reqap } from "../lib/reqap";
import { COLOR_RESF_GREEN } from "../styles";
import { severityToBadge, severityToText, typeToText } from "./enumToText";

export const ShowErrata = () => {
  const { id } = useParams<{ id: string }>();

  const cardBg = useColorModeValue("white", "gray.800");
  const sideBg = useColorModeValue("gray.100", "gray.700");
  const linkBlue = useColorModeValue("blue.600", "blue.300");
  const linkPurple = useColorModeValue("purple.600", "purple.300");

  const [errata, setErrata] = useState<V2Advisory>();
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);

  useEffect(() => {
    if (!id) return;

    const fetchData = async () => {
      setIsLoading(true);
      const [err, res] = await reqap(() => getAdvisory(id));

      setIsLoading(false);

      if (err || !res) {
        setIsError(true);
        setErrata(undefined);
        return;
      }

      setIsError(false);
      setErrata(res.advisory);
    };

    fetchData();
  }, [id]);

  return (
    <Box
      w="100%"
      h="100%"
      display="flex"
      flexDirection="column"
      p={4}
      alignItems="stretch"
      maxWidth="1300px"
      m="auto"
    >
      <Breadcrumb mb={4}>
        <BreadcrumbItem>
          <BreadcrumbLink as={RouterLink} to="/">
            Product Errata
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbItem>
          <BreadcrumbLink isCurrentPage>{id}</BreadcrumbLink>
        </BreadcrumbItem>
      </Breadcrumb>
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
        errata && (
          <>
            <HStack
              alignItems="center"
              backgroundColor={cardBg}
              py="2"
              px="4"
              spacing="6"
              mb={2}
            >
              {severityToBadge(errata.severity, errata.type, 40)}
              <VStack alignItems="stretch" spacing="0" flexGrow={1}>
                <HStack justifyContent="space-between">
                  <Text fontSize="lg" fontWeight="bold">
                    {errata.name}
                  </Text>
                </HStack>
                <Text fontSize="sm">{errata.synopsis}</Text>
                {errata.source && (
                  <Text fontSize="xs" mt={1} color="gray.500">
                    Source:{" "}
                    <Link
                      href={errata.source.url}
                      isExternal
                      color={linkBlue}
                      _visited={{ color: linkPurple }}
                    >
                      {errata.source.vendor} {errata.source.name}
                    </Link>
                    , used under{" "}
                    <Link
                      href={errata.source.licenseUrl}
                      isExternal
                      color={linkBlue}
                      _visited={{ color: linkPurple }}
                    >
                      {errata.source.license}
                    </Link>
                    , with modifications.
                  </Text>
                )}
              </VStack>
            </HStack>
            <Tabs backgroundColor={cardBg} p="2">
              <TabList>
                <Tab>Erratum</Tab>
                <Tab>Updated Packages</Tab>
              </TabList>
              <Box
                display="flex"
                flexDir="row"
                alignItems="stretch"
                flexWrap="wrap"
                justifyContent="space-between"
              >
                <TabPanels maxWidth="850px" px="2">
                  <TabPanel>
                    <Heading as="h2" size="md">
                      Topic
                    </Heading>
                    {errata.topic?.split("\n").map((p, i) => (
                      <Text key={i} mt={2}>
                        {p}
                      </Text>
                    ))}
                    <Heading as="h2" size="md" mt={4}>
                      Description
                    </Heading>
                    {errata.description?.split("\n").map((p, i) => (
                      <Text key={i} mt={2}>
                        {p}
                      </Text>
                    ))}
                  </TabPanel>
                  <TabPanel>
                    <VStack alignItems="flex-start" spacing="6">
                      {Object.keys(errata.rpms ?? {}).map((product) => (
                        <div key={product}>
                          <Heading as="h2" size="lg" mb={4} fontWeight="300">
                            {product}
                          </Heading>
                          <Heading as="h3" size="md" mt={2}>
                            SRPMs
                          </Heading>
                          <UnorderedList pl="4">
                            {errata.rpms?.[product]?.nvras
                              ?.filter((x) => x.includes(".src.rpm"))
                              .map((x) => (
                                <ListItem key={x}>{x}</ListItem>
                              ))}
                          </UnorderedList>
                          <Heading as="h3" size="md" mt={2}>
                            RPMs
                          </Heading>
                          <UnorderedList pl="4">
                            {errata.rpms?.[product]?.nvras
                              ?.filter((x) => !x.includes(".src.rpm"))
                              .map((x) => (
                                <ListItem key={x}>{x}</ListItem>
                              ))}
                          </UnorderedList>
                        </div>
                      ))}
                    </VStack>
                  </TabPanel>
                </TabPanels>
                <VStack
                  py="4"
                  px="8"
                  alignItems="flex-start"
                  minWidth="300px"
                  spacing="5"
                  flexShrink={0}
                  backgroundColor={sideBg}
                >
                  <Text>
                    <b>Issued:</b>{" "}
                    {errata.publishedAt
                      ? new Date(errata.publishedAt).toLocaleDateString()
                      : ""}
                  </Text>
                  <Text>
                    <b>Type:</b> {typeToText(errata.type)}
                  </Text>
                  {errata.type === "TYPE_SECURITY" && (
                    <Text>
                      <b>Severity:</b> {severityToText(errata.severity)}
                    </Text>
                  )}
                  <Box>
                    <Text fontWeight="bold">
                      Affected Product
                      {(errata.affectedProducts?.length ?? 0) > 1 ? "s" : ""}
                    </Text>
                    <UnorderedList>
                      {errata.affectedProducts?.map((x, idx) => (
                        <ListItem key={idx}>{x}</ListItem>
                      ))}
                    </UnorderedList>
                  </Box>
                  <Box>
                    <Text fontWeight="bold">Fixes</Text>
                    <UnorderedList>
                      {errata.fixes?.map((x, idx) => (
                        <ListItem key={idx}>
                          <Link
                            href={x.sourceLink}
                            isExternal
                            color={linkBlue}
                            _visited={{ color: linkPurple }}
                          >
                            {x.sourceBy} - {x.ticket}
                          </Link>
                        </ListItem>
                      ))}
                    </UnorderedList>
                  </Box>
                  <Box>
                    <Text fontWeight="bold">CVEs</Text>
                    <UnorderedList>
                      {errata.cves?.length ? (
                        errata.cves.map((x, idx) => {
                          const text = `${x.name}${
                            x.sourceBy !== "" ? ` (Source: ${x.sourceBy})` : ""
                          }`;

                          return (
                            <ListItem key={idx}>
                              {x.sourceLink === "" ? (
                                <span>{text}</span>
                              ) : (
                                <Link
                                  href={x.sourceLink}
                                  isExternal
                                  color={linkBlue}
                                  _visited={{ color: linkPurple }}
                                >
                                  {text}
                                </Link>
                              )}
                            </ListItem>
                          );
                        })
                      ) : (
                        <ListItem>No CVEs</ListItem>
                      )}
                    </UnorderedList>
                  </Box>
                  <Box>
                    <Text fontWeight="bold">References</Text>
                    <UnorderedList>
                      {errata.references?.length ? (
                        errata.references.map((x, idx) => (
                          <ListItem key={idx}>{x}</ListItem>
                        ))
                      ) : (
                        <ListItem>No references</ListItem>
                      )}
                    </UnorderedList>
                  </Box>
                </VStack>
              </Box>
            </Tabs>
          </>
        )
      )}
    </Box>
  );
};
