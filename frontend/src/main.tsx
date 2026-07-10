import React from "react";
import ReactDOM from "react-dom/client";
import * as ReactJSXRuntime from "react/jsx-runtime";
import i18next from "i18next";
import * as ReactI18next from "react-i18next";
import { BrowserRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import "./index.css";
import "./lib/i18n";

// Single shared QueryClient for all data-fetching hooks (useQuery/useMutation)
// across the app. staleTime > 0 avoids an extra refetch immediately after a
// query's own consumer re-mounts (e.g. re-opening a settings panel), while
// still refetching in the background on window refocus - the same
// "background-revalidate, don't show a spinner again" behavior several
// pages used to hand-roll individually (see e.g. AdminSmtpPage's
// hasFetchedStatus guard, now unnecessary once that page migrates).
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: 1,
    },
  },
});

// Expose host singletons for module bundles loaded via Blob URL.
// Modules declare these as externals and read them from window.__MODULAB_HOST__
// so both host and module share the same React instance (avoids hook errors).
(window as unknown as Record<string, unknown>).__MODULAB_HOST__ = {
  React,
  ReactDOM,
  ReactJSXRuntime,
  i18next,
  ReactI18next,
};

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
