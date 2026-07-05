import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import jsxA11y from "eslint-plugin-jsx-a11y";
import tseslint from "typescript-eslint";

// Flat config (ESLint 10). Mirrors the official Vite React+TS template's
// base setup (js.configs.recommended + tseslint.configs.recommended +
// react-hooks + react-refresh) and adds jsx-a11y on top, since that's the
// gap the pre-V1 code review actually found real issues in (missing
// alt text, etc.) that the type checker alone can't catch.
export default tseslint.config(
  { ignores: ["dist"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
      "jsx-a11y": jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // eslint-plugin-react-hooks v7 added a React Compiler-readiness
      // rule set (purity/refs/set-state-in-effect/error-boundaries) on top
      // of the classic rules-of-hooks/exhaustive-deps. They flag patterns
      // that are fine today under plain React 19 (no compiler in use) but
      // could behave differently under the compiler: setting a loading
      // flag at the top of a data-fetching effect, storing the latest
      // callback in a ref during render, seeding a ref with Date.now().
      // These are established patterns used throughout this codebase, not
      // bugs - downgraded to warnings so they stay visible (e.g. as a
      // starting checklist if this project ever adopts the compiler)
      // without blocking every push on a large, purely defensive refactor.
      "react-hooks/purity": "warn",
      "react-hooks/refs": "warn",
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/error-boundaries": "warn",

      // Default depth (2) doesn't look far enough for labels that wrap an
      // input plus a small text block (label > div > p > text), which is a
      // real, valid a11y pattern (OPMLSelectionModal's feed list) - not a
      // missing label. 4 covers that nesting without disabling the check.
      "jsx-a11y/label-has-associated-control": ["error", { depth: 4 }],
    },
  },
);
