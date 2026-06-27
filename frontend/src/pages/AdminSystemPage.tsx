import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  getSystemStatus,
  updateOIDC,
  updateDNSChallenge,
  type SystemStatus,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system — post-wizard OIDC and DNS-challenge editing, plus group prefix
// display. Super-admin only (same gate as SMTP). The group prefix is read-only
// here: changing it requires re-running the Setup Wizard's group-prefix step,
// since it controls which OIDC groups map to which roles.
export default function AdminSystemPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // OIDC form state
  const [oidcIssuer, setOidcIssuer] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [oidcSecret, setOidcSecret] = useState("");
  const [savingOIDC, setSavingOIDC] = useState(false);
  const [savedOIDC, setSavedOIDC] = useState(false);

  // DNS-challenge form state
  const [dnsProvider, setDnsProvider] = useState("");
  const [dnsCredentials, setDnsCredentials] = useState("");
  const [savingDNS, setSavingDNS] = useState(false);
  const [savedDNS, setSavedDNS] = useState(false);

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

    getSystemStatus(token)
      .then((s) => {
        setStatus(s);
        if (s.oidc.configured) {
          setOidcIssuer(s.oidc.issuer_url ?? "");
          setOidcClientId(s.oidc.client_id ?? "");
        }
        if (s.dns_challenge.configured) {
          setDnsProvider(s.dns_challenge.provider ?? "");
        }
      })
      .catch(() => setError(t("admin.system.load_error")));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  async function handleOIDCSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    if (!oidcIssuer.trim() || !oidcClientId.trim()) {
      setError(t("admin.system.oidc_validation_error"));
      return;
    }
    setSavingOIDC(true);
    setError(null);
    setSavedOIDC(false);
    try {
      const result = await updateOIDC(token, {
        issuer_url: oidcIssuer.trim(),
        client_id: oidcClientId.trim(),
        client_secret: oidcSecret.trim() || undefined,
      });
      setStatus((prev) => prev ? { ...prev, oidc: result } : prev);
      setOidcSecret("");
      setSavedOIDC(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("admin.system.save_error"));
    } finally {
      setSavingOIDC(false);
    }
  }

  async function handleDNSSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    if (!dnsProvider.trim()) {
      setError(t("admin.system.dns_validation_error"));
      return;
    }
    setSavingDNS(true);
    setError(null);
    setSavedDNS(false);
    try {
      const result = await updateDNSChallenge(token, {
        provider: dnsProvider.trim(),
        credentials: dnsCredentials.trim() || undefined,
      });
      setStatus((prev) => prev ? { ...prev, dns_challenge: result } : prev);
      setDnsCredentials("");
      setSavedDNS(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("admin.system.save_error"));
    } finally {
      setSavingDNS(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10 space-y-10">
        <div>
          <h1 className="text-xl font-semibold mb-1">{t("admin.system.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system.subtitle")}</p>
        </div>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        {/* Group prefix — read-only */}
        <Section title={t("admin.system.group_prefix_title")}>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
            {t("admin.system.group_prefix_hint")}
          </p>
          <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2.5 text-sm font-mono text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300">
            {status?.group_prefix || <span className="text-gray-400 dark:text-gray-600">{t("admin.system.not_configured")}</span>}
          </div>
        </Section>

        {/* OIDC */}
        <Section title={t("admin.system.oidc_title")}>
          <StatusBadge configured={status?.oidc.configured ?? false} />
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 mt-2">
            {t("admin.system.oidc_hint")}
          </p>
          {savedOIDC && (
            <p className="mb-3 text-sm text-green-700 dark:text-green-400">{t("admin.system.saved")}</p>
          )}
          <form onSubmit={handleOIDCSubmit} className="space-y-4">
            <Field label={t("setup.step2.issuer_url")}>
              <input
                type="url"
                value={oidcIssuer}
                onChange={(e) => setOidcIssuer(e.target.value)}
                placeholder="https://auth.example.com"
                className={inputClass}
              />
            </Field>
            <Field label={t("setup.step2.client_id")}>
              <input
                type="text"
                value={oidcClientId}
                onChange={(e) => setOidcClientId(e.target.value)}
                className={inputClass}
              />
            </Field>
            <Field label={t("setup.step2.client_secret")}>
              <input
                type="password"
                value={oidcSecret}
                onChange={(e) => setOidcSecret(e.target.value)}
                placeholder={status?.oidc.configured ? t("admin.system.secret_placeholder_existing") : ""}
                className={inputClass}
              />
            </Field>
            <button
              type="submit"
              disabled={savingOIDC}
              className={btnPrimary}
            >
              {savingOIDC ? t("admin.system.saving") : t("admin.system.save_oidc")}
            </button>
          </form>
        </Section>

        {/* DNS-challenge */}
        <Section title={t("admin.system.dns_title")}>
          <StatusBadge configured={status?.dns_challenge.configured ?? false} />
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 mt-2">
            {t("admin.system.dns_hint")}
          </p>
          {savedDNS && (
            <p className="mb-3 text-sm text-green-700 dark:text-green-400">{t("admin.system.saved")}</p>
          )}
          <form onSubmit={handleDNSSubmit} className="space-y-4">
            <Field label={t("setup.step3.dns_provider")}>
              <input
                type="text"
                value={dnsProvider}
                onChange={(e) => setDnsProvider(e.target.value)}
                placeholder="cloudflare"
                className={inputClass}
              />
            </Field>
            <Field label={t("setup.step3.api_credentials")}>
              <textarea
                value={dnsCredentials}
                onChange={(e) => setDnsCredentials(e.target.value)}
                rows={4}
                placeholder={
                  status?.dns_challenge.configured
                    ? t("admin.system.credentials_placeholder_existing")
                    : t("setup.step3.api_credentials_placeholder")
                }
                className={`${inputClass} resize-none`}
              />
            </Field>
            <button
              type="submit"
              disabled={savingDNS}
              className={btnPrimary}
            >
              {savingDNS ? t("admin.system.saving") : t("admin.system.save_dns")}
            </button>
          </form>
        </Section>
      </div>
    </AppShell>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";

const btnPrimary =
  "w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";

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
      <h2 className="mb-3 text-base font-semibold text-gray-800 dark:text-gray-200">{title}</h2>
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
