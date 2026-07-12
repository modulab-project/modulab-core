import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "../locales/en.json";
import de from "../locales/de.json";
import fr from "../locales/fr.json";
import es from "../locales/es.json";
import nl from "../locales/nl.json";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "de", "fr", "es", "nl"],
    resources: {
      en: { translation: en },
      de: { translation: de },
      fr: { translation: fr },
      es: { translation: es },
      nl: { translation: nl },
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
