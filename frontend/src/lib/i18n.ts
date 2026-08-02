import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "../locales/en.json";

// Only English ships in the entry bundle (it's the fallback language, so it
// must always be available synchronously). The other 4 locales are loaded
// on demand via ensureLanguage() below, keeping ~200 KB of translations out
// of the initial JS payload for users who end up on "en" anyway.
const LAZY_LOCALES = ["de", "fr", "es", "nl"] as const;
type LazyLocale = (typeof LAZY_LOCALES)[number];

function isLazyLocale(lng: string): lng is LazyLocale {
  return (LAZY_LOCALES as readonly string[]).includes(lng);
}

const pendingLoads = new Map<string, Promise<void>>();

/**
 * Ensures the translation bundle for `lng` (or its base language, e.g.
 * "de-DE" -> "de") is loaded into i18next before it's used. Safe to call
 * repeatedly - already-loaded/loading languages are deduped. Resolves
 * immediately for "en" (always bundled) and unsupported languages.
 */
export function ensureLanguage(lng: string): Promise<void> {
  const base = lng.split("-")[0];
  if (!isLazyLocale(base)) return Promise.resolve();
  if (i18n.hasResourceBundle(base, "translation")) return Promise.resolve();

  let promise = pendingLoads.get(base);
  if (!promise) {
    promise = import(`../locales/${base}.json`).then((mod) => {
      i18n.addResourceBundle(base, "translation", mod.default, true, true);
    });
    pendingLoads.set(base, promise);
  }
  return promise;
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "de", "fr", "es", "nl"],
    partialBundledLanguages: true,
    resources: {
      en: { translation: en },
    },
    interpolation: {
      // React already escapes values
      escapeValue: false,
    },
    detection: {
      // No localStorage: the user's actual choice lives in users.ui_language
      // (DB) and is applied by AppShell's getUserPrefs effect once a session
      // exists. Before login (or if that fetch hasn't run yet), fall back to
      // the browser's own language - never cache the result client-side, so
      // there is nothing here that could go stale or leak across devices.
      order: ["navigator"],
      caches: [],
    },
  });

export default i18n;
