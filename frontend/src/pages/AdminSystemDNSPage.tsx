import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { getSystemStatus, updateDNSChallenge } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

export default function AdminSystemDNSPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [configured, setConfigured] = useState(false);
  const [provider, setProvider] = useState("");
  const [credentials, setCredentials] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    const token = getSessionToken();
    if (!token) return;
    getSystemStatus(token)
      .then((s) => {
        setConfigured(s.dns_challenge.configured);
        if (s.dns_challenge.configured) {
          setProvider(s.dns_challenge.provider ?? "");
        }
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    if (!provider.trim()) {
      setMsg({ ok: false, text: t("admin.system.dns_validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      await updateDNSChallenge(token, {
        provider: provider.trim(),
        credentials: credentials.trim() || undefined,
      });
      setConfigured(true);
      setCredentials("");
      setMsg({ ok: true, text: t("admin.system.saved") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
    } finally {
      setSaving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <BackLink />
        <div className="mb-6 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.system.dns_title")}</h1>
          <StatusDot configured={configured} t={t} />
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.system.dns_hint")}</p>
        {msg && <Msg msg={msg} />}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t("setup.step3.dns_provider")}>
            <input type="text" value={provider} onChange={(e) => setProvider(e.target.value)}
              placeholder="cloudflare" className={inputClass} />
          </Field>
          <Field label={t("setup.step3.api_credentials")}>
            <textarea value={credentials} onChange={(e) => setCredentials(e.target.value)} rows={4}
              placeholder={configured ? t("admin.system.credentials_placeholder_existing") : t("setup.step3.api_credentials_placeholder")}
              className={`${inputClass} resize-none`} />
          </Field>
          <button type="submit" disabled={saving} className={btnPrimary}>
            {saving ? t("admin.system.saving") : t("admin.system.save_dns")}
          </button>
        </form>
      </div>
    </AppShell>
  );
}

function BackLink() {
  const { t } = useTranslation();
  return (
    <Link to="/admin/system"
      className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
      <i className="ti ti-arrow-left text-[14px]" />
      {t("admin.system.back")}
    </Link>
  );
}

function StatusDot({ configured, t }: { configured: boolean; t: (k: string) => string }) {
  return (
    <span className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
      <span className={`h-2 w-2 rounded-full ${configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`} />
      {configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
    </span>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } }) {
  return (
    <p className={`mb-4 text-sm ${msg.ok ? "text-green-700 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}>
      {msg.text}
    </p>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
    </label>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";

const btnPrimary =
  "w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";
