// Shared TanStack Query keys used from more than one component/page, so the
// underlying cache entry is actually shared (query keys match by value, not
// reference - but keeping the canonical array in one place avoids typos
// silently creating two separate cache entries for what should be the same
// data).
export const USER_FEEDS_QUERY_KEY = ["user-feeds"] as const;
export const ACTIVE_MODULES_QUERY_KEY = ["active-modules"] as const;
