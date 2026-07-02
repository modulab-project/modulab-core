// Schema allowlist for URLs rendered as <a href> from data that isn't fully
// trusted (SearXNG search results, RSS feed items, admin-entered quick
// links). Without this check a "javascript:" URL stored in any of those
// sources would execute on click — see the Core security review (2026-07)
// for the specific call sites this closes (Home.tsx search/RSS results,
// QuickLinksGrid.tsx, StorePage.tsx).
//
// This is a client-side defense in depth, not the primary control: the
// backend should already be treating these values as untrusted data, not
// markup. Kept intentionally permissive on the "what counts as http(s)"
// side (no host allowlist) since legitimate search results and feeds link
// to arbitrary external sites — the goal is only to block script-executing
// schemes, not to curate destinations.

const ALLOWED_SCHEMES = ["http:", "https:"];

/**
 * Returns href unchanged if it's a safe, renderable link target (http(s), or
 * a root-relative path like "/settings"), otherwise returns undefined so the
 * caller can omit the href attribute entirely (rendering inert text/a
 * non-clickable element instead of a link to an unsafe destination).
 */
export function safeHref(href: string | null | undefined): string | undefined {
  if (!href) return undefined;
  const trimmed = href.trim();
  if (trimmed === "") return undefined;

  // Root-relative paths ("/foo", "/foo?bar") never carry a scheme and are
  // always safe — same-origin navigation only.
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    return trimmed;
  }

  try {
    // Base URL only matters for resolving relative paths, which are already
    // handled above; for absolute URLs the parsed scheme is what we check.
    const parsed = new URL(trimmed, window.location.origin);
    if (ALLOWED_SCHEMES.includes(parsed.protocol)) {
      return trimmed;
    }
  } catch {
    // Not a parseable URL at all — treat as unsafe rather than guessing.
  }
  return undefined;
}
