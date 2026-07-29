import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { getSystemStatus, updateOIDC, deleteOIDCConfig } from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { isSuperAdminRole } from "../lib/roles";
import { AppShell } from "../components/AppShell";
import { ReauthBanner } from "../components/ReauthBanner";

export default function AdminSystemOIDCPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [configured, setConfigured] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  // Read-only - set once in the Setup Wizard, never editable from here (see
  // its hint text below). Moved onto this page from the /admin/system hub
  // (2026-07-08): it's OIDC-specific data with nowhere else it makes sense
  // to show, not a standalone configurable area of its own.
  const [groupPrefix, setGroupPrefix] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [reauthRequired, setReauthRequired] = useState(false);
  const hasFetched = useRef(false);
  // Backend now gates PATCH/DELETE /v1/admin/oidc behind requireRecentLogin
  // (RequireAdminReauthMiddleware) - this is the trust root for every
  // login on the instance, so changing it gets the same step-up treatment
  // as locking/deleting a user (AdminUsersPage.tsx). See that page's
  // identical pattern for why reauth/returnPath are passed to startLogin.
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setMsg(null);
  });

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    getSystemStatus()
      .then((s) => {
        setConfigured(s.oidc.configured);
        if (s.oidc.configured) {
          setIssuer(s.oidc.issuer_url ?? "");
          setClientId(s.oidc.client_id ?? "");
        }
        setGroupPrefix(s.group_prefix ?? null);
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!issuer.trim() || !clientId.trim()) {
      setMsg({ ok: false, text: t("admin.system.oidc_validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      await updateOIDC({
        issuer_url: issuer.trim(),
        client_id: clientId.trim(),
        client_secret: secret.trim() || undefined,
      });
      setConfigured(true);
      setSecret("");
      setMsg({ ok: true, text: t("admin.system.saved") });
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    if (removing) return;
    setRemoving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      await deleteOIDCConfig();
      setConfigured(false);
      setIssuer(""); setClientId(""); setSecret("");
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system.save_error") });
      }
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <BackLink />
        <div className="mb-6 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.system.oidc_title")}</h1>
          <StatusDot configured={configured} t={t} />
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.system.oidc_hint")}</p>

        {/* Group prefix — read-only, set once by the Setup Wizard. Shown
            here (not as its own hub card) since it has no configuration
            surface of its own to justify one. */}
        <div className="mb-6 rounded-xl border border-gray-200 p-4 dark:border-gray-800">
          <div className="flex items-center gap-2.5">
            <i className="ti ti-tag text-[18px] text-gray-400" />
            <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              {t("admin.system.group_prefix_title")}
            </span>
          </div>
          <p className="mt-2 mb-2 text-xs text-gray-500 dark:text-gray-400">
            {t("admin.system.group_prefix_hint")}
          </p>
          <div className="rounded-lg border border-gray-100 bg-gray-50 px-2.5 py-1.5 text-xs font-mono text-gray-700 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-300">
            {groupPrefix || <span className="text-gray-400 dark:text-gray-600">{t("admin.system.not_configured")}</span>}
          </div>
        </div>

        {msg && <Msg msg={msg} />}
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t("setup.step2.issuer_url")}>
            <input type="url" value={issuer} onChange={(e) => setIssuer(e.target.value)}
              placeholder="https://auth.example.com" className={inputClass} />
          </Field>
          <Field label={t("setup.step2.client_id")}>
            <input type="text" value={clientId} onChange={(e) => setClientId(e.target.value)}
              className={inputClass} />
          </Field>
          <Field label={configured ? `${t("setup.step2.client_secret")} (${t("admin.system.secret_placeholder_existing")})` : t("setup.step2.client_secret")}>
            <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)}
              className={inputClass} />
          </Field>
          <div className="flex gap-3">
            <button type="submit" disabled={saving} className={`flex-1 ${btnPrimary}`}>
              {saving ? t("admin.system.saving") : t("admin.system.save")}
            </button>
            {configured && (
              <button type="button" disabled={removing} onClick={handleRemove}
                className="flex-1 rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
                {removing ? t("admin.system.oidc.removing") : t("admin.system.oidc.remove")}
              </button>
            )}
          </div>
        </form>
      </div>
    </AppShell>
  );
}

// ── shared helpers ──────────────────────────────────────────────────────────

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
      <span className={`h-2 w-2 rounded-full ${configured ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
      {configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
    </span>
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
