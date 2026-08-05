import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { geoipStatus as fetchGeoipStatus, configureGeoip, deleteGeoipConfig, type GeoIPStatus } from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { isSuperAdminRole } from "../lib/roles";
import { AppShell } from "../components/AppShell";
import { ReauthBanner } from "../components/ReauthBanner";

// Admin settings page for MaxMind GeoLite2 (City + ASN) IP geolocation -
// same placement/auth-tier/step-up-reauth pattern as AdminSystemSmtpPage.tsx
// (ongoing Admin Panel, not the Setup Wizard; POST/DELETE gated behind a
// recent login). Unlike SMTP there is no "test" affordance: saving new
// credentials already triggers an immediate download attempt server-side
// (see GeoIPConfigureHandler's triggerDownload), so last_update_at/
// last_update_error in the very next status response already tells the
// admin whether it worked.
export default function AdminSystemGeoIPPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [status, setStatus] = useState<GeoIPStatus | null>(null);
  const [accountId, setAccountId] = useState("");
  const [licenseKey, setLicenseKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [reauthRequired, setReauthRequired] = useState(false);
  const hasFetched = useRef(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setMsg(null);
  });

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    fetchGeoipStatus()
      .then((s) => {
        setStatus(s);
        if (s.configured) {
          setAccountId(s.account_id ?? "");
        }
      })
      .catch(() => setMsg({ ok: false, text: t("admin.geoip.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!accountId.trim()) {
      setMsg({ ok: false, text: t("admin.geoip.validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      const result = await configureGeoip({ account_id: accountId.trim(), license_key: licenseKey });
      setStatus(result);
      setLicenseKey("");
      if (result.last_update_error) {
        setMsg({ ok: false, text: `${t("admin.geoip.saved")} ${t("admin.geoip.download_failed", { error: result.last_update_error })}` });
      } else {
        setMsg({ ok: true, text: t("admin.geoip.saved") });
      }
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.geoip.save_error") });
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    if (!window.confirm(t("admin.geoip.remove_confirm"))) return;
    setRemoving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      await deleteGeoipConfig();
      setStatus({ configured: false });
      setAccountId("");
      setLicenseKey("");
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.geoip.remove_error") });
      }
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-3xl py-10">
        <div className="mb-1 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.geoip.title")}</h1>
          {status && (
            <span className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
              <span className={`h-2 w-2 rounded-full ${status.configured ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
              {status.configured ? t("admin.geoip.status_configured") : t("admin.geoip.status_not_configured")}
            </span>
          )}
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.geoip.subtitle")}</p>
        {status?.configured && (
          <p className="mb-4 text-xs text-gray-500 dark:text-gray-400">
            {status.last_update_at
              ? t("admin.geoip.last_update", { time: new Date(status.last_update_at).toLocaleString() })
              : t("admin.geoip.no_update_yet")}
          </p>
        )}
        {status?.configured && status.last_update_error && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">
            {t("admin.geoip.download_failed", { error: status.last_update_error })}
          </p>
        )}
        {msg && <Msg msg={msg} />}
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t("admin.geoip.account_id")}>
            <input type="text" value={accountId} onChange={(e) => setAccountId(e.target.value)}
              placeholder="123456" className={inputClass} />
          </Field>
          <Field label={status?.configured ? `${t("admin.geoip.license_key")} (${t("admin.geoip.license_key_placeholder_existing")})` : t("admin.geoip.license_key")}>
            <input type="password" value={licenseKey} onChange={(e) => setLicenseKey(e.target.value)}
              className={inputClass} />
          </Field>
          <p className="text-xs text-gray-500 dark:text-gray-400">{t("admin.geoip.hint")}</p>
          <div className="flex gap-3">
            <button type="submit" disabled={saving} className={`flex-1 ${btnPrimary}`}>
              {saving ? t("admin.geoip.saving") : t("admin.geoip.save")}
            </button>
            {status?.configured && (
              <button type="button" disabled={removing} onClick={handleRemove} className={`flex-1 ${btnDanger}`}>
                {removing ? t("admin.geoip.action.removing") : t("admin.geoip.action.remove")}
              </button>
            )}
          </div>
        </form>
      </div>
    </AppShell>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } }) {
  return (
    <p className={`mb-4 text-sm ${msg.ok ? "text-teal-700 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
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
  "rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";

const btnDanger =
  "rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950";
