import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { getSystemStatus, updateDNSChallenge, deleteDNSConfig, verifyDNSChallenge, type DNSVerifyResult } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

const DNS_PROVIDERS = [
  "cloudflare",
  "route53",
  "digitalocean",
  "hetzner",
  "inwx",
  "namecheap",
  "gandi",
  "ovh",
  "linode",
  "vultr",
  "azure",
  "google",
  "dnsimple",
  "porkbun",
  "njalla",
  "__custom__",
] as const;

export default function AdminSystemDNSPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [configured, setConfigured] = useState(false);
  const [provider, setProvider] = useState("");
  const [customProvider, setCustomProvider] = useState("");
  const [credentials, setCredentials] = useState("");

  // Derived: is the current provider one of the known list?
  const isCustom = provider === "__custom__";
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [verifyResult, setVerifyResult] = useState<DNSVerifyResult | null>(null);
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
          const saved = s.dns_challenge.provider ?? "";
          if (DNS_PROVIDERS.slice(0, -1).includes(saved as never)) {
            setProvider(saved);
          } else if (saved) {
            setProvider("__custom__");
            setCustomProvider(saved);
          }
        }
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    const effectiveProvider = isCustom ? customProvider.trim() : provider.trim();
    if (!effectiveProvider) {
      setMsg({ ok: false, text: t("admin.system.dns_validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    setVerifyResult(null);
    try {
      await updateDNSChallenge(token, {
        provider: effectiveProvider,
        credentials: credentials.trim() || undefined,
      });
      setConfigured(true);
      setCredentials("");
      setMsg({ ok: true, text: t("admin.system.saved") });
      // Verify key after saving.
      setVerifying(true);
      try {
        const result = await verifyDNSChallenge(token);
        setVerifyResult(result);
      } catch {
        // Non-fatal – save succeeded, verify failed to reach backend.
      } finally {
        setVerifying(false);
      }
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token || removing) return;
    setRemoving(true);
    setMsg(null);
    try {
      await deleteDNSConfig(token);
      setConfigured(false);
      setVerifyResult(null);
      setProvider(""); setCustomProvider(""); setCredentials("");
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
    } finally {
      setRemoving(false);
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
        {verifyResult && <VerifyMsg result={verifyResult} verifying={verifying} t={t} />}
        {verifying && !verifyResult && (
          <p className="mb-4 text-sm text-gray-400 dark:text-gray-500">{t("admin.system.dns.verifying")}</p>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t("admin.system.dns_provider")}>
            <select value={provider} onChange={(e) => setProvider(e.target.value)} className={inputClass}>
              <option value="" disabled>— {t("admin.system.dns_provider")} —</option>
              <option value="cloudflare">Cloudflare</option>
              <option value="route53">AWS Route 53</option>
              <option value="digitalocean">DigitalOcean</option>
              <option value="hetzner">Hetzner</option>
              <option value="inwx">INWX</option>
              <option value="namecheap">Namecheap</option>
              <option value="gandi">Gandi</option>
              <option value="ovh">OVH</option>
              <option value="linode">Linode / Akamai</option>
              <option value="vultr">Vultr</option>
              <option value="azure">Azure DNS</option>
              <option value="google">Google Cloud DNS</option>
              <option value="dnsimple">DNSimple</option>
              <option value="porkbun">Porkbun</option>
              <option value="njalla">Njalla</option>
              <option value="__custom__">{t("admin.system.dns_provider_custom")}</option>
            </select>
          </Field>
          {isCustom && (
            <Field label="">
              <input
                type="text"
                value={customProvider}
                onChange={(e) => setCustomProvider(e.target.value)}
                placeholder={t("admin.system.dns_provider_placeholder")}
                className={inputClass}
              />
            </Field>
          )}
          <Field label={t("admin.system.api_credentials")}>
            <textarea value={credentials} onChange={(e) => setCredentials(e.target.value)} rows={4}
              placeholder={configured ? t("admin.system.credentials_placeholder_existing") : t("admin.system.api_credentials_placeholder")}
              className={`${inputClass} resize-none`} />
          </Field>
          <div className="flex gap-3">
            <button type="submit" disabled={saving} className={`flex-1 ${btnPrimary}`}>
              {saving ? t("admin.system.saving") : t("admin.system.save")}
            </button>
            {configured && (
              <button type="button" disabled={removing} onClick={handleRemove}
                className="flex-1 rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
                {removing ? t("admin.system.dns.removing") : t("admin.system.dns.remove")}
              </button>
            )}
          </div>
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

function VerifyMsg({ result, verifying, t }: { result: DNSVerifyResult; verifying: boolean; t: (k: string) => string }) {
  if (verifying) return null;
  if (!result.supported) {
    return (
      <p className="mb-4 text-sm text-gray-400 dark:text-gray-500">
        {t("admin.system.dns.verify_unsupported")}
      </p>
    );
  }
  return (
    <p className={`mb-4 text-sm ${result.valid ? "text-green-700 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}>
      {result.valid ? t("admin.system.dns.verify_valid") : `${t("admin.system.dns.verify_invalid")}: ${result.message}`}
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
  "rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";
