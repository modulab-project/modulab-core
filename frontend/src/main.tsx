import React from "react";
import ReactDOM from "react-dom/client";
import * as ReactJSXRuntime from "react/jsx-runtime";
import i18next from "i18next";
import * as ReactI18next from "react-i18next";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";
import "./lib/i18n";

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
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
