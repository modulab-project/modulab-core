import { QueryClient } from "@tanstack/react-query";

// Single shared QueryClient for all data-fetching hooks (useQuery/useMutation)
// across the app. staleTime > 0 avoids an extra refetch immediately after a
// query's own consumer re-mounts (e.g. re-opening a settings panel), while
// still refetching in the background on window refocus.
//
// Lives in its own module (not inline in main.tsx) specifically so
// session.ts's clearSessionToken() can import and clear it directly - see
// that function's comment for why this matters: ModuLab is designed to run
// as a shared, always-on browser homepage (Home.tsx's top-of-file comment),
// so this tab's cache can outlive any one person's session.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: 1,
    },
  },
});
