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

export default function AdminSystemGeneralPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [settings, setSettings] = useState<GeneralSettings | null>(null);
  const [language, setLanguage] = useState<GeneralSettings["system_language"]>("en");
  const [instanceName, setInstanceName] = useState("");
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
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system_general.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  const dirty = settings !== null && (
    language !== settings.system_language || instanceName.trim() !== settings.instance_name
  );

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (!instanceName.trim()) {
      setMsg({ ok: false, text: t("admin.system_general.validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      const result = await adminPatchGeneralSettings({
        system_language: language,
        instance_name: instanceName.trim(),
      });
      setSettings(result);
      setLanguage(result.system_language);
      setInstanceName(result.instance_name);
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
