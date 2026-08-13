import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "../locales/en.json";

// Auto-discovered from every locales/*.json file present at build time,
// via Vite's import.meta.glob - adding a new locale is then just "drop a
// new xx.json file in locales/", with nothing to register by hand here or
// in the language switcher (AppShell reads AVAILABLE_LANGUAGES/
// getLanguageEndonym below instead of a hardcoded <option> list). Replaces
// the old manually-maintained LAZY_LOCALES tuple, which someone adding a
// 6th language would otherwise have to remember to update in lockstep with
// the actual json file.
const localeModules = import.meta.glob<{ default: Record<string, unknown> }>("../locales/*.json");

// Sorted for a deterministic, filesystem-order-independent option list.
export const AVAILABLE_LANGUAGES: string[] = Object.keys(localeModules)
  .map((path) => path.match(/([a-z]{2,3})\.json$/)?.[1])
  .filter((code): code is string => Boolean(code))
  .sort();

/**
 * Native endonym for a language code ("de" -> "Deutsch", "fr" -> "français"),
 * derived from Intl.DisplayNames rather than a hardcoded name table - asking
 * a language for its own name (passing its own code as the DisplayNames
 * locale) is what actually produces the endonym. A language switcher must
 * show each option in its own language regardless of the current UI locale
 * (standard convention), which is exactly what this does automatically for
 * whatever codes AVAILABLE_LANGUAGES contains. Falls back to the bare code
 * if the runtime lacks Intl.DisplayNames or doesn't recognize it.
 */
export function getLanguageEndonym(code: string): string {
  try {
    return new Intl.DisplayNames([code], { type: "language" }).of(code) ?? code;
  } catch {
    return code;
  }
}

// Only English ships in the entry bundle (it's the fallback language, so it
// must always be available synchronously). Every other discovered locale is
// loaded on demand via ensureLanguage() below, keeping the other locales'
// translation payloads out of the initial JS for users who end up on "en"
// anyway.
const LAZY_LOCALES = AVAILABLE_LANGUAGES.filter((code) => code !== "en");

function isLazyLocale(lng: string): boolean {
  return LAZY_LOCALES.includes(lng);
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
    const loader = localeModules[`../locales/${base}.json`];
    if (!loader) return Promise.resolve();
    promise = loader().then((mod) => {
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
    supportedLngs: AVAILABLE_LANGUAGES,
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
