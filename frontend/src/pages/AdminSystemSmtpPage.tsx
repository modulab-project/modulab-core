import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { smtpStatus as fetchSmtpStatus, configureSmtp, deleteSmtpConfig, testSmtp, type SMTPStatus } from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { isSuperAdminRole } from "../lib/roles";
import { AppShell } from "../components/AppShell";
import { ReauthBanner } from "../components/ReauthBanner";

export default function AdminSystemSmtpPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [status, setStatus] = useState<SMTPStatus | null>(null);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("465");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [encryption, setEncryption] = useState("tls");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testAddress, setTestAddress] = useState("");
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [reauthRequired, setReauthRequired] = useState(false);
  const hasFetched = useRef(false);
  // Backend now gates POST /v1/admin/smtp/configure and DELETE /v1/admin/smtp
  // behind requireRecentLogin (RequireSuperAdminReauthMiddleware) - not the
  // test-send endpoint, which changes nothing. Same step-up pattern as
  // AdminSystemOIDCPage.tsx/AdminUsersPage.tsx.
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setMsg(null);
  });

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    fetchSmtpStatus()
      .then((s) => {
        setStatus(s);
        if (s.configured) {
          setHost(s.host ?? "");
          setPort(String(s.port ?? 465));
          setUsername(s.username ?? "");
          setFromAddress(s.from_address ?? "");
          setEncryption(s.encryption ?? "tls");
        }
      })
      .catch(() => setMsg({ ok: false, text: t("admin.smtp.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setMsg({ ok: false, text: t("admin.smtp.validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      const result = await configureSmtp({
        host: host.trim(), port: parsedPort, username: username.trim(),
        password, from_address: fromAddress.trim(), encryption,
      });
      setStatus(result);
      setPassword("");
      setMsg({ ok: true, text: t("admin.smtp.saved") });
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.save_error") });
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(e: FormEvent) {
    e.preventDefault();
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setTestResult({ ok: false, text: t("admin.smtp.validation_error") });
      return;
    }
    if (!testAddress.trim()) {
      setTestResult({ ok: false, text: t("admin.smtp.test_address_required") });
      return;
    }
    setTestBusy(true);
    setTestResult(null);
    try {
      await testSmtp({
        host: host.trim(),
        port: parsedPort,
        username: username.trim(),
        password,
        from_address: fromAddress.trim(),
        encryption,
        to: testAddress.trim(),
      });
      setTestResult({ ok: true, text: t("admin.smtp.test_ok") });
    } catch (err) {
      setTestResult({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.test_error") });
    } finally {
      setTestBusy(false);
    }
  }

  async function handleRemove() {
    if (!window.confirm(t("admin.smtp.remove_confirm"))) return;
    setRemoving(true);
    setMsg(null);
    setReauthRequired(false);
    try {
      await deleteSmtpConfig();
      setStatus({ configured: false });
      setHost(""); setPort("465"); setUsername(""); setPassword(""); setFromAddress(""); setEncryption("tls");
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.remove_error") });
      }
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <BackLink />
        <div className="mb-1 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.smtp.title")}</h1>
          {status && (
            <span className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
              <span className={`h-2 w-2 rounded-full ${status.configured ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
              {status.configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
            </span>
          )}
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.smtp.subtitle")}</p>
        {status && !status.configured && (
          <p className="mb-4 text-sm text-amber-600 dark:text-amber-400">{t("admin.smtp.warning_not_configured")}</p>
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
          <Field label={t("admin.smtp.host")}>
            <input type="text" value={host} onChange={(e) => setHost(e.target.value)}
              placeholder="mail.example.com" className={inputClass} />
          </Field>
          <Field label={t("admin.smtp.port")}>
            <input type="number" value={port} onChange={(e) => setPort(e.target.value)}
              className={inputClass} />
          </Field>
          <Field label={t("admin.smtp.username")}>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
              placeholder={t("admin.smtp.username_placeholder")} className={inputClass} />
          </Field>
          <Field label={status?.configured ? `${t("admin.smtp.password")} (${t("admin.smtp.password_placeholder_existing")})` : t("admin.smtp.password")}>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className={inputClass} />
          </Field>
          <Field label={t("admin.smtp.from_address")}>
            <input type="email" value={fromAddress} onChange={(e) => setFromAddress(e.target.value)}
              placeholder="modulab@example.com" className={inputClass} />
          </Field>
          <Field label={t("admin.smtp.encryption")}>
            <select value={encryption} onChange={(e) => setEncryption(e.target.value)} className={inputClass}>
              <option value="none">{t("admin.smtp.enc_none")}</option>
              <option value="starttls">{t("admin.smtp.enc_starttls")}</option>
              <option value="tls">{t("admin.smtp.enc_tls")}</option>
            </select>
          </Field>
          <div className="flex gap-3">
            <button type="submit" disabled={saving} className={`flex-1 ${btnPrimary}`}>
              {saving ? t("admin.smtp.saving") : t("admin.smtp.save")}
            </button>
            {status?.configured && (
              <button type="button" disabled={removing} onClick={handleRemove} className={`flex-1 ${btnDanger}`}>
                {removing ? t("admin.smtp.action.removing") : t("admin.smtp.action.remove")}
              </button>
            )}
          </div>
        </form>

        {/* Test-send — always visible so admin can verify config before/after saving */}
        <div className="mt-6 rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800/50">
          <p className="mb-1 text-sm font-medium text-gray-700 dark:text-gray-300">{t("admin.smtp.test_title")}</p>
          <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">{t("admin.smtp.test_hint")}</p>
          <form onSubmit={handleTest} className="flex gap-2">
            <input
              type="email"
              value={testAddress}
              onChange={(e) => setTestAddress(e.target.value)}
              placeholder={t("admin.smtp.test_address_placeholder")}
              className={`min-w-0 flex-1 ${inputClass}`}
            />
            <button
              type="submit"
              disabled={testBusy || !testAddress.trim()}
              className={btnSecondary}
            >
              {testBusy ? t("admin.smtp.test_sending") : t("admin.smtp.test_button")}
            </button>
          </form>
          {testResult && (
            <p className={`mt-2 text-xs ${testResult.ok ? "text-teal-600 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
              {testResult.text}
            </p>
          )}
        </div>
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

const btnSecondary =
  "flex-none rounded-lg border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-700";
