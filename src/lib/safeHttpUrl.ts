/**
 * Allow only credential-free http(s) URLs for API-sourced hrefs.
 *
 * Pass `base` to accept paths such as `/api/v3/csaf/...`; they resolve against it.
 */
export function safeHttpUrl(value: unknown, base?: string): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    const parsed = new URL(trimmed, base);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return undefined;
    }
    if (parsed.username || parsed.password) {
      return undefined;
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}
