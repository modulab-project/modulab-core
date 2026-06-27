import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { configureSmtp, deleteSmtpConfig, smtpStatus, type SMTPStatus } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// "/admin/smtp" - spec section 3.5's "SMTP-Konfiguration im Admin-Panel",
// the relay the mail queue (backend/internal/mail) sends through for the
// account lifecycle notifications (approve/lock/unlock) that go out even
// to someone not currently connected to /v1/events. Super-admin only,
// stricter than AdminUsersPage's org-admin-or-above gate - this is
// system-level infrastructure config (same tier as the Setup Wizard's
// OIDC step), not day-to-day user management, mirroring the backend's own
// auth.RequireSuperAdminMiddleware.
//
// There is deliberately no "show current password" field: the backend
// (setup.SMTPStatusResponse) never returns it, the same treatment
// OIDCStatusResponse already gives the OIDC client secret. Leaving the
// password field empty on a resubmit is interpreted by the backend as
// "use an unauthenticated relay", not "keep the existing one" - the
// placeholder text below says so explicitly to avoid an admin
// accidentally wiping a working password by saving the form without
// re-entering it.
export default function AdminSmtpPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [status, setStatus] = useState<SMTPStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);

  const [host, setHost] = useState("");
  const [port, setPort] = useState("587");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [encryption, setEncryption] = useState("starttls");

  // useAuthenticatedSession polls /v1/auth/me every 15s and hands back a
  // brand-new Session object each time (see its own doc comment on why -
  // catching a lock/delete that revoked this tab's session). Without this
  // guard, that 15s re-render re-ran the fetch below on every poll and
  // overwrote whatever the admin had typed but not yet saved - any
  // unsaved field, not just Encryption, would silently snap back to
  // the persisted value a few seconds after being changed. The fetch
  // itself should only ever happen once, right after the session first
  // resolves to a super-admin - not every time that object's identity
  // changes.
  const hasFetchedStatus = useRef(false);

  useEffect(() => {
    if (!session) {
      return;
    }
    // Not a super-admin - this page isn't for them, same "bounce home
    // rather than show a dead end" treatment AdminUsersPage gives a
    // non-admin. session.role === "super-admin" directly (not
    // isAdminRole, which also accepts org-admin) since the backend gate
    // here is genuinely stricter.
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetchedStatus.current) {
      return;
    }
    hasFetchedStatus.current = true;
    const token = getSessionToken();
    if (!token) {
      return;
    }
    smtpStatus(token)
      .then((s) => {
        setStatus(s);
        if (s.configured) {
          setHost(s.host ?? "");
          setPort(String(s.port ?? 587));
          setUsername(s.username ?? "");
          setFromAddress(s.from_address ?? "");
          setEncryption(s.encryption ?? "starttls");
        }
      })
      .catch(() => setError(t("admin.smtp.load_error")));
  }, [session, navigate]);

  if (loading || !session || session.role !== "super-admin") {
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) {
      return;
    }
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setError(t("admin.smtp.validation_error"));
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const result = await configureSmtp(token, {
        host: host.trim(),
        port: parsedPort,
        username: username.trim(),
        password,
        from_address: fromAddress.trim(),
        encryption,
      });
      setStatus(result);
      setPassword("");
      setSavedAt(Date.now());
    } catch (err) {
      const message = err instanceof Error ? err.message : t("admin.smtp.save_error");
      setError(message);
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token) {
      return;
    }
    if (!window.confirm(t("admin.smtp.remove_confirm"))) {
      return;
    }
    setRemoving(true);
    setError(null);
    try {
      await deleteSmtpConfig(token);
      setStatus({ configured: false });
      setHost("");
      setPort("587");
      setUsername("");
      setPassword("");
      setFromAddress("");
      setEncryption("starttls");
      setSavedAt(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : t("admin.smtp.remove_error");
      setError(message);
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <div className="mb-1 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.smtp.title")}</h1>
          {status && (
            <span className="flex items-center gap-1.5 text-xs font-medium text-gray-500 dark:text-gray-400">
              <span className={`h-2 w-2 rounded-full ${status.configured ? "bg-green-600" : "bg-red-600"}`} />
              {status.configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
            </span>
          )}
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.smtp.subtitle")}
        </p>

        {status && !status.configured && (
          <p className="mb-4 text-sm text-amber-600 dark:text-amber-400">
            {t("admin.smtp.warning_not_configured")}
          </p>
        )}
        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {savedAt && !error && (
          <p className="mb-4 text-sm text-green-700 dark:text-green-400">{t("admin.smtp.saved")}</p>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t("setup.step6.host")}>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="mail.example.com"
              className={inputClass}
            />
          </Field>
          <Field label={t("setup.step6.port")}>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className={inputClass}
            />
          </Field>
          <Field label={t("setup.step6.username")}>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={t("admin.smtp.username_placeholder")}
              className={inputClass}
            />
          </Field>
          <Field label={t("setup.step6.password")}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={status?.configured ? t("admin.smtp.password_placeholder_existing") : ""}
              className={inputClass}
            />
          </Field>
          <Field label={t("setup.step6.from_address")}>
            <input
              type="email"
              value={fromAddress}
              onChange={(e) => setFromAddress(e.target.value)}
              placeholder="modulab@example.com"
              className={inputClass}
            />
          </Field>
          <Field label={t("setup.step6.encryption")}>
            <select
              value={encryption}
              onChange={(e) => setEncryption(e.target.value)}
              className={inputClass}
            >
              <option value="none">{t("setup.step6.enc_none")}</option>
              <option value="starttls">{t("setup.step6.enc_starttls")}</option>
              <option value="tls">{t("setup.step6.enc_tls")}</option>
            </select>
          </Field>

          <button
            type="submit"
            disabled={saving}
            className="w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400"
          >
            {saving ? t("admin.smtp.saving") : t("admin.smtp.save")}
          </button>

          {status?.configured && (
            <button
              type="button"
              disabled={removing}
              onClick={handleRemove}
              className="w-full rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
            >
              {removing ? t("admin.smtp.action.removing") : t("admin.smtp.action.remove")}
            </button>
          )}
        </form>
      </div>
    </AppShell>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
    </label>
  );
}
