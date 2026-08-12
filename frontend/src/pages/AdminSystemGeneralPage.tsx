import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { adminGetGeneralSettings, adminPatchGeneralSettings, type GeneralSettings } from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { isSuperAdminRole } from "../lib/roles";
import { AppShell } from "../components/AppShell";

// /admin/system/general — "Sprache & Region" / "Instanz-Identität": the
// system-wide UI language default and the display name substituted for
// "ModuLab" in outgoing system mail (see backend's mail.CurrentBranding /
// templates.go). Deliberately its own small page rather than a tab on
// AdminSystemLimitsPage - see adminapi.AdminGeneralHandler's doc comment
// for why identity/localization and operational limits are kept apart.
//
// Unlike SMTP/OIDC, neither field is a secret, so this page has no
// reauth (RequireAdminReauthMiddleware) gate - same treatment
// AdminSystemLimitsPage gives its own non-secret settings.
const LANGUAGES: Array<{ value: GeneralSettings["system_language"]; flag: string }> = [
  { value: "en", flag: "🇬🇧" },
  { value: "de", flag: "🇩🇪" },
  { value: "nl", flag: "🇳🇱" },
  { value: "es", flag: "🇪🇸" },
  { value: "fr", flag: "🇫🇷" },
];

// Full IANA Time Zone Database name list, straight from the browser/Node
// runtime rather than a hand-maintained array - Intl.supportedValuesOf is
// baseline-available in every browser this app already targets (Chrome
// 99+/Firefox 102+/Safari 15.4+). Falls back to a small hardcoded list on
// the rare runtime that lacks it (older WebViews), so the dropdown is never
// simply empty. Memoized as a module-level constant since the supported set
// cannot change during a page's lifetime.
const FALLBACK_TIMEZONES = ["UTC", "Europe/Berlin", "Europe/London", "America/New_York", "America/Los_Angeles", "Asia/Tokyo"];
const ALL_TIMEZONES: string[] =
  typeof Intl !== "undefined" && "supportedValuesOf" in Intl
    ? (Intl as unknown as { supportedValuesOf: (key: string) => string[] }).supportedValuesOf("timeZone")
    : FALLBACK_TIMEZONES;

// The browser's own guess at the user's timezone (IANA name), used by the
// "use my browser timezone" button below. Not auto-applied on load - the
// system timezone is an instance-wide setting any admin might open this
// page from a different zone than the one that should actually govern
// scheduling (e.g. a datacenter's own zone), so this is offered as a
// one-click convenience, never a silent default.
function detectBrowserTimezone(): string | null {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    return null;
  }
}

export default function AdminSystemGeneralPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [settings, setSettings] = useState<GeneralSettings | null>(null);
  const [language, setLanguage] = useState<GeneralSettings["system_language"]>("en");
  const [instanceName, setInstanceName] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    adminGetGeneralSettings()
      .then((s) => {
        setSettings(s);
        setLanguage(s.system_language);
        setInstanceName(s.instance_name);
        setTimezone(s.system_timezone);
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system_general.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  const dirty = settings !== null && (
    language !== settings.system_language
    || instanceName.trim() !== settings.instance_name
    || timezone !== settings.system_timezone
  );

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (!instanceName.trim()) {
      setMsg({ ok: false, text: t("admin.system_general.validation_error") });
      return;
    }
    if (!timezone.trim() || !ALL_TIMEZONES.includes(timezone.trim())) {
      setMsg({ ok: false, text: t("admin.system_general.timezone_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      const result = await adminPatchGeneralSettings({
        system_language: language,
        instance_name: instanceName.trim(),
        system_timezone: timezone.trim(),
      });
      setSettings(result);
      setLanguage(result.system_language);
      setInstanceName(result.instance_name);
      setTimezone(result.system_timezone);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system_general.save_error") });
    } finally {
      setSaving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-3xl py-6 sm:py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("admin.system_general.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.system_general.subtitle")}</p>

        {msg && (
          <p className={`mb-4 text-sm ${msg.ok ? "text-teal-700 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
            {msg.text}
          </p>
        )}

        <form onSubmit={handleSave} className="space-y-8">
          <Group title={t("admin.system_general.section_language")}>
            <div>
              <label className="mb-2 block text-xs text-gray-500 dark:text-gray-400">
                {t("admin.system_general.system_language_label")}
              </label>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {LANGUAGES.map((l) => (
                  <button
                    key={l.value}
                    type="button"
                    onClick={() => setLanguage(l.value)}
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2.5 text-sm ${
                      language === l.value
                        ? "border-teal-500 bg-teal-50 font-medium text-teal-700 dark:border-teal-500 dark:bg-teal-950 dark:text-teal-300"
                        : "border-gray-200 text-gray-600 hover:border-gray-300 dark:border-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <span className="text-base leading-none">{l.flag}</span>
                    {t(`admin.system_general.lang_${l.value}`)}
                  </button>
                ))}
              </div>
              <p className="mt-2 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.system_general.system_language_hint")}
              </p>
            </div>
          </Group>

          <Group title={t("admin.system_general.section_identity")}>
            <div>
              <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
                {t("admin.system_general.instance_name_label")}
              </label>
              <input
                type="text"
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                placeholder="ModuLab"
                className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
              />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.system_general.instance_name_hint")}
              </p>
            </div>
          </Group>

          <Group title={t("admin.system_general.section_timezone")}>
            <div>
              <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
                {t("admin.system_general.timezone_label")}
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  list="system-timezone-options"
                  value={timezone}
                  onChange={(e) => setTimezone(e.target.value)}
                  placeholder="UTC"
                  className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                />
                <datalist id="system-timezone-options">
                  {ALL_TIMEZONES.map((tz) => (
                    <option key={tz} value={tz} />
                  ))}
                </datalist>
                <button
                  type="button"
                  onClick={() => {
                    const detected = detectBrowserTimezone();
                    if (detected) setTimezone(detected);
                  }}
                  className="shrink-0 rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-600 hover:border-gray-300 dark:border-gray-700 dark:text-gray-300"
                >
                  {t("admin.system_general.timezone_detect_button")}
                </button>
              </div>
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.system_general.timezone_hint")}
              </p>
            </div>
          </Group>

          <div className="flex justify-end">
            <button type="submit" disabled={saving || !dirty}
              className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400">
              {saved ? t("admin.system_general.saved") : saving ? t("common.saving") : t("common.save")}
            </button>
          </div>
        </form>
      </div>
    </AppShell>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {title}
      </p>
      <div className="space-y-4 rounded-2xl border border-gray-200 bg-white px-4 py-4 dark:border-gray-800 dark:bg-gray-900">
        {children}
      </div>
    </div>
  );
}
