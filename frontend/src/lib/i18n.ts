import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "../locales/en.json";
import de from "../locales/de.json";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "de"],
    resources: {
      en: { translation: en },
      de: { translation: de },
    },
    interpolation: {
      // React already escapes values
      escapeValue: false,
    },
    detection: {
      // Check localStorage first, then browser language, cache in localStorage
      order: ["localStorage", "navigator"],
      caches: ["localStorage"],
      lookupLocalStorage: "modulab_language",
    },
  });

export default i18n;
