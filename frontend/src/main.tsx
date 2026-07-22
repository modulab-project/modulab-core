import React from "react";
import ReactDOM from "react-dom/client";
import * as ReactJSXRuntime from "react/jsx-runtime";
import i18next from "i18next";
import * as ReactI18next from "react-i18next";
import { BrowserRouter } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./lib/queryClient";
import App from "./App";
import "./index.css";
import "./lib/i18n";
// Self-hosted Tabler Icons webfont (used throughout the app as ti/ti-*
// classes) - replaces the previous <link> to cdnjs.cloudflare.com in
// index.html. Bundled and fingerprinted by Vite like any other asset, so
// the app no longer makes a third-party request just to render its own
// icons, and the CSP's style-src/font-src no longer need a
// cdnjs.cloudflare.com exception (see nginx.conf).
import "@tabler/icons-webfont/dist/tabler-icons.min.css";

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
