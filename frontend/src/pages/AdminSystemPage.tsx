import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  getSystemStatus,
  updateOIDC,
  updateDNSChallenge,
  smtpStatus as fetchSmtpStatus,
  configureSmtp,
  deleteSmtpConfig,
  searxngStatus as fetchSearxngStatus,
  configureSearxng,
  deleteSearxngConfig,
  type SystemStatus,
  type SMTPStatus,
  type SearXNGStatus,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system — unified system configuration page (super-admin only).
// Combines all post-wizard configuration into one place:
//   • Group prefix    (read-only)
//   • OIDC            (editable)
//   • DNS-Challenge   (editable)
//   • SMTP            (editable + deletable)
//   • SearXNG         (editable + deletable)
//   • KI-Anbieter     (link card → /admin/ai, which has its own complex UI)
export default function AdminSystemPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  // ── system status (OIDC + DNS + prefix) ─────────────────────────────────
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);

  // ── OIDC form ────────────────────────────────────────────────────────────
  const [oidcIssuer, setOidcIssuer] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [oidcSecret, setOidcSecret] = useState("");
  const [savingOIDC, setSavingOIDC] = useState(false);
  const [oidcMsg, setOidcMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // ── DNS-Challenge form ───────────────────────────────────────────────────
  const [dnsProvider, setDnsProvider] = useState("");
  const [dnsCredentials, setDnsCredentials] = useState("");
  const [savingDNS, setSavingDNS] = useState(false);
  const [dnsMsg, setDnsMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // ── SMTP form ────────────────────────────────────────────────────────────
  const [smtp, setSmtp] = useState<SMTPStatus | null>(null);
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpUsername, setSmtpUsername] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [smtpFrom, setSmtpFrom] = useState("");
  const [smtpEncryption, setSmtpEncryption] = useState("starttls");
  const [savingSMTP, setSavingSMTP] = useState(false);
  const [removingSMTP, setRemovingSMTP] = useState(false);
  const [smtpMsg, setSmtpMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // ── SearXNG form ─────────────────────────────────────────────────────────
  const [searxng, setSearxng] = useState<SearXNGStatus | null>(null);
  const [searxngUrl, setSearxngUrl] = useState("");
  const [searxngMaxResults, setSearxngMaxResults] = useState(25);
  const [searxngFetchPages, setSearxngFetchPages] = useState(2);
  const [savingSearxng, setSavingSearxng] = useState(false);
  const [removingSearxng, setRemovingSearxng] = useState(false);
  const [searxngMsg, setSearxngMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const [loadError, setLoadError] = useState<string | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;

    const token = getSessionToken();
    if (!token) return;

    Promise.all([
      getSystemStatus(token),
      fetchSmtpStatus(token),
      fetchSearxngStatus(token),
    ])
      .then(([sys, smtpSt, searxngSt]) => {
        // System status (OIDC + DNS + prefix)
        setSystemStatus(sys);
        if (sys.oidc.configured) {
          setOidcIssuer(sys.oidc.issuer_url ?? "");
          setOidcClientId(sys.oidc.client_id ?? "");
        }
        if (sys.dns_challenge.configured) {
          setDnsProvider(sys.dns_challenge.provider ?? "");
        }

        // SMTP
        setSmtp(smtpSt);
        if (smtpSt.configured) {
          setSmtpHost(smtpSt.host ?? "");
          setSmtpPort(String(smtpSt.port ?? 587));
          setSmtpUsername(smtpSt.username ?? "");
          setSmtpFrom(smtpSt.from_address ?? "");
          setSmtpEncryption(smtpSt.encryption ?? "starttls");
        }

        // SearXNG
        setSearxng(searxngSt);
        if (searxngSt.configured && searxngSt.url) setSearxngUrl(searxngSt.url);
        setSearxngMaxResults(searxngSt.max_results);
        setSearxngFetchPages(searxngSt.fetch_pages);
      })
      .catch(() => setLoadError(t("admin.system.load_error")));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  // ── OIDC submit ──────────────────────────────────────────────────────────
  async function handleOIDCSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    if (!oidcIssuer.trim() || !oidcClientId.trim()) {
      setOidcMsg({ ok: false, text: t("admin.system.oidc_validation_error") });
      return;
    }
    setSavingOIDC(true);
    setOidcMsg(null);
    try {
      const result = await updateOIDC(token, {
        issuer_url: oidcIssuer.trim(),
        client_id: oidcClientId.trim(),
        client_secret: oidcSecret.trim() || undefined,
      });
      setSystemStatus((prev) => prev ? { ...prev, oidc: result } : prev);
      setOidcSecret("");
      setOidcMsg({ ok: true, text: t("admin.system.saved") });
    } catch (err) {
      setOidcMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
    } finally {
      setSavingOIDC(false);
    }
  }

  // ── DNS submit ───────────────────────────────────────────────────────────
  async function handleDNSSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    if (!dnsProvider.trim()) {
      setDnsMsg({ ok: false, text: t("admin.system.dns_validation_error") });
      return;
    }
    setSavingDNS(true);
    setDnsMsg(null);
    try {
      const result = await updateDNSChallenge(token, {
        provider: dnsProvider.trim(),
        credentials: dnsCredentials.trim() || undefined,
      });
      setSystemStatus((prev) => prev ? { ...prev, dns_challenge: result } : prev);
      setDnsCredentials("");
      setDnsMsg({ ok: true, text: t("admin.system.saved") });
    } catch (err) {
      setDnsMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
    } finally {
      setSavingDNS(false);
    }
  }

  // ── SMTP submit ──────────────────────────────────────────────────────────
  async function handleSMTPSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    const parsedPort = parseInt(smtpPort, 10);
    if (!smtpHost.trim() || !smtpFrom.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setSmtpMsg({ ok: false, text: t("admin.smtp.validation_error") });
      return;
    }
    setSavingSMTP(true);
    setSmtpMsg(null);
    try {
      const result = await configureSmtp(token, {
        host: smtpHost.trim(),
        port: parsedPort,
        username: smtpUsername.trim(),
        password: smtpPassword,
        from_address: smtpFrom.trim(),
        encryption: smtpEncryption,
      });
      setSmtp(result);
      setSmtpPassword("");
      setSmtpMsg({ ok: true, text: t("admin.smtp.saved") });
    } catch (err) {
      setSmtpMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.save_error") });
    } finally {
      setSavingSMTP(false);
    }
  }

  async function handleSMTPRemove() {
    const token = getSessionToken();
    if (!token) return;
    if (!window.confirm(t("admin.smtp.remove_confirm"))) return;
    setRemovingSMTP(true);
    setSmtpMsg(null);
    try {
      await deleteSmtpConfig(token);
      setSmtp({ configured: false });
      setSmtpHost(""); setSmtpPort("587"); setSmtpUsername("");
      setSmtpPassword(""); setSmtpFrom(""); setSmtpEncryption("starttls");
      setSmtpMsg(null);
    } catch (err) {
      setSmtpMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.remove_error") });
    } finally {
      setRemovingSMTP(false);
    }
  }

  // ── SearXNG submit ───────────────────────────────────────────────────────
  async function handleSearxngSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token || savingSearxng) return;
    setSavingSearxng(true);
    setSearxngMsg(null);
    try {
      const result = await configureSearxng(token, {
        url: searxngUrl.trim(),
        max_results: searxngMaxResults,
        fetch_pages: searxngFetchPages,
      });
      setSearxng(result);
      setSearxngMsg({ ok: true, text: t("admin.searxng.saved") });
    } catch (err) {
      setSearxngMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setSavingSearxng(false);
    }
  }

  async function handleSearxngRemove() {
    const token = getSessionToken();
    if (!token || removingSearxng) return;
    setSearxngMsg(null);
    setRemovingSearxng(true);
    try {
      await deleteSearxngConfig(token);
      setSearxng({ configured: false, max_results: 25, fetch_pages: 2 });
      setSearxngUrl(""); setSearxngMaxResults(25); setSearxngFetchPages(2);
      setSearxngMsg(null);
    } catch (err) {
      setSearxngMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setRemovingSearxng(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-lg py-10 space-y-10">
        <div>
          <h1 className="text-xl font-semibold mb-1">{t("admin.system.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system.subtitle")}</p>
        </div>

        {loadError && <p className="text-sm text-red-600 dark:text-red-400">{loadError}</p>}

        {/* ── 1. Gruppen-Präfix ── */}
        <Section title={t("admin.system.group_prefix_title")}>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
            {t("admin.system.group_prefix_hint")}
          </p>
          <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2.5 text-sm font-mono text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300">
            {systemStatus?.group_prefix || (
              <span className="text-gray-400 dark:text-gray-600">{t("admin.system.not_configured")}</span>
            )}
          </div>
        </Section>

        {/* ── 2. OIDC ── */}
        <Section title={t("admin.system.oidc_title")}>
          <StatusBadge configured={systemStatus?.oidc.configured ?? false} />
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 mt-2">
            {t("admin.system.oidc_hint")}
          </p>
          <Msg msg={oidcMsg} />
          <form onSubmit={handleOIDCSubmit} className="space-y-4">
            <Field label={t("setup.step2.issuer_url")}>
              <input type="url" value={oidcIssuer} onChange={(e) => setOidcIssuer(e.target.value)}
                placeholder="https://auth.example.com" className={inputClass} />
            </Field>
            <Field label={t("setup.step2.client_id")}>
              <input type="text" value={oidcClientId} onChange={(e) => setOidcClientId(e.target.value)}
                className={inputClass} />
            </Field>
            <Field label={t("setup.step2.client_secret")}>
              <input type="password" value={oidcSecret} onChange={(e) => setOidcSecret(e.target.value)}
                placeholder={systemStatus?.oidc.configured ? t("admin.system.secret_placeholder_existing") : ""}
                className={inputClass} />
            </Field>
            <button type="submit" disabled={savingOIDC} className={btnPrimary}>
              {savingOIDC ? t("admin.system.saving") : t("admin.system.save_oidc")}
            </button>
          </form>
        </Section>

        {/* ── 3. DNS-Challenge ── */}
        <Section title={t("admin.system.dns_title")}>
          <StatusBadge configured={systemStatus?.dns_challenge.configured ?? false} />
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 mt-2">
            {t("admin.system.dns_hint")}
          </p>
          <Msg msg={dnsMsg} />
          <form onSubmit={handleDNSSubmit} className="space-y-4">
            <Field label={t("setup.step3.dns_provider")}>
              <input type="text" value={dnsProvider} onChange={(e) => setDnsProvider(e.target.value)}
                placeholder="cloudflare" className={inputClass} />
            </Field>
            <Field label={t("setup.step3.api_credentials")}>
              <textarea value={dnsCredentials} onChange={(e) => setDnsCredentials(e.target.value)} rows={3}
                placeholder={
                  systemStatus?.dns_challenge.configured
                    ? t("admin.system.credentials_placeholder_existing")
                    : t("setup.step3.api_credentials_placeholder")
                }
                className={`${inputClass} resize-none`} />
            </Field>
            <button type="submit" disabled={savingDNS} className={btnPrimary}>
              {savingDNS ? t("admin.system.saving") : t("admin.system.save_dns")}
            </button>
          </form>
        </Section>

        {/* ── 4. SMTP ── */}
        <Section title={t("admin.smtp.title")}>
          <StatusBadge configured={smtp?.configured ?? false} />
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 mt-2">
            {t("admin.smtp.subtitle")}
          </p>
          {smtp && !smtp.configured && (
            <p className="mb-3 text-sm text-amber-600 dark:text-amber-400">
              {t("admin.smtp.warning_not_configured")}
            </p>
          )}
          <Msg msg={smtpMsg} />
          <form onSubmit={handleSMTPSubmit} className="space-y-4">
            <Field label={t("setup.step6.host")}>
              <input type="text" value={smtpHost} onChange={(e) => setSmtpHost(e.target.value)}
                placeholder="mail.example.com" className={inputClass} />
            </Field>
            <Field label={t("setup.step6.port")}>
              <input type="number" value={smtpPort} onChange={(e) => setSmtpPort(e.target.value)}
                className={inputClass} />
            </Field>
            <Field label={t("setup.step6.username")}>
              <input type="text" value={smtpUsername} onChange={(e) => setSmtpUsername(e.target.value)}
                placeholder={t("admin.smtp.username_placeholder")} className={inputClass} />
            </Field>
            <Field label={t("setup.step6.password")}>
              <input type="password" value={smtpPassword} onChange={(e) => setSmtpPassword(e.target.value)}
                placeholder={smtp?.configured ? t("admin.smtp.password_placeholder_existing") : ""}
                className={inputClass} />
            </Field>
            <Field label={t("setup.step6.from_address")}>
              <input type="email" value={smtpFrom} onChange={(e) => setSmtpFrom(e.target.value)}
                placeholder="modulab@example.com" className={inputClass} />
            </Field>
            <Field label={t("setup.step6.encryption")}>
              <select value={smtpEncryption} onChange={(e) => setSmtpEncryption(e.target.value)}
                className={inputClass}>
                <option value="none">{t("setup.step6.enc_none")}</option>
                <option value="starttls">{t("setup.step6.enc_starttls")}</option>
                <option value="tls">{t("setup.step6.enc_tls")}</option>
              </select>
            </Field>
            <button type="submit" disabled={savingSMTP} className={btnPrimary}>
              {savingSMTP ? t("admin.smtp.saving") : t("admin.smtp.save")}
            </button>
            {smtp?.configured && (
              <button type="button" disabled={removingSMTP} onClick={handleSMTPRemove}
                className={btnDanger}>
                {removingSMTP ? t("admin.smtp.action.removing") : t("admin.smtp.action.remove")}
              </button>
            )}
          </form>
        </Section>

        {/* ── 5. SearXNG ── */}
        <Section title={t("admin.searxng.title")}>
          <div className="flex items-center gap-2 mb-2">
            <span className={`h-2 w-2 rounded-full ${searxng?.configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`} />
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {searxng?.configured ? t("admin.searxng.status_configured") : t("admin.searxng.status_not_configured")}
            </span>
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            {t("admin.searxng.subtitle")}
          </p>
          <Msg msg={searxngMsg} />
          <form onSubmit={handleSearxngSubmit} className="space-y-4">
            <Field label={t("admin.searxng.url_label")}>
              <input type="url" required value={searxngUrl} onChange={(e) => setSearxngUrl(e.target.value)}
                placeholder="https://search.example.com" className={inputClass} />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.url_hint")}</p>
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label={t("admin.searxng.max_results_label")}>
                <input type="number" min={1} max={100} value={searxngMaxResults}
                  onChange={(e) => setSearxngMaxResults(Math.max(1, Math.min(100, Number(e.target.value))))}
                  className={inputClass} />
                <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.max_results_hint")}</p>
              </Field>
              <Field label={t("admin.searxng.fetch_pages_label")}>
                <input type="number" min={1} max={5} value={searxngFetchPages}
                  onChange={(e) => setSearxngFetchPages(Math.max(1, Math.min(5, Number(e.target.value))))}
                  className={inputClass} />
                <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.fetch_pages_hint")}</p>
              </Field>
            </div>
            <div className="flex gap-3">
              <button type="submit" disabled={savingSearxng}
                className="rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400">
                {savingSearxng ? t("admin.searxng.saving") : t("admin.searxng.save")}
              </button>
              {searxng?.configured && (
                <button type="button" disabled={removingSearxng} onClick={handleSearxngRemove}
                  className="rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
                  {removingSearxng ? t("admin.searxng.action.removing") : t("admin.searxng.action.remove")}
                </button>
              )}
            </div>
          </form>
          {!searxng?.configured && (
            <div className="mt-6 rounded-xl border border-gray-200 p-4 dark:border-gray-800">
              <p className="mb-1 text-sm font-medium">{t("admin.searxng.no_instance_title")}</p>
              <p className="mb-2 text-xs text-gray-500 dark:text-gray-400">{t("admin.searxng.no_instance_body")}</p>
              <pre className="overflow-x-auto rounded-lg bg-gray-900 px-3 py-2 text-xs text-gray-100">
                {"docker compose --profile search up -d"}
              </pre>
            </div>
          )}
        </Section>

        {/* ── 6. KI-Anbieter (link card) ── */}
        <Section title={t("admin.ai.title")}>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            {t("admin.ai.subtitle")}
          </p>
          <Link
            to="/admin/ai"
            className="flex items-center justify-between rounded-xl border border-gray-200 px-4 py-3 text-sm hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-900"
          >
            <span className="flex items-center gap-2.5">
              <i className="ti ti-sparkles text-[16px] text-teal-600 dark:text-teal-400" />
              <span className="font-medium">{t("admin.system.ai_manage_link")}</span>
            </span>
            <i className="ti ti-chevron-right text-gray-400" />
          </Link>
        </Section>
      </div>
    </AppShell>
  );
}

// ── shared styles ────────────────────────────────────────────────────────────

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";

const btnPrimary =
  "w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";

const btnDanger =
  "w-full rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950";

// ── small helpers ────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
    </label>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h2 className="mb-3 border-b border-gray-100 pb-2 text-base font-semibold text-gray-800 dark:border-gray-800 dark:text-gray-200">
        {title}
      </h2>
      {children}
    </div>
  );
}

function StatusBadge({ configured }: { configured: boolean }) {
  const { t } = useTranslation();
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 dark:text-gray-400">
      <span className={`h-2 w-2 rounded-full ${configured ? "bg-green-600" : "bg-red-600"}`} />
      {configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
    </span>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return (
    <p className={`mb-3 text-sm ${msg.ok ? "text-green-700 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}>
      {msg.text}
    </p>
  );
}
