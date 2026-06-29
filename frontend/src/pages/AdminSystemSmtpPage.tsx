import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { smtpStatus as fetchSmtpStatus, configureSmtp, deleteSmtpConfig, type SMTPStatus } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

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
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    const token = getSessionToken();
    if (!token) return;
    fetchSmtpStatus(token)
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

  if (loading || !session || session.role !== "super-admin") return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setMsg({ ok: false, text: t("admin.smtp.validation_error") });
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      const result = await configureSmtp(token, {
        host: host.trim(), port: parsedPort, username: username.trim(),
        password, from_address: fromAddress.trim(), encryption,
      });
      setStatus(result);
      setPassword("");
      setMsg({ ok: true, text: t("admin.smtp.saved") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.save_error") });
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token) return;
    if (!window.confirm(t("admin.smtp.remove_confirm"))) return;
    setRemoving(true);
    setMsg(null);
    try {
      await deleteSmtpConfig(token);
      setStatus({ configured: false });
      setHost(""); setPort("465"); setUsername(""); setPassword(""); setFromAddress(""); setEncryption("tls");
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.smtp.remove_error") });
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
              <span className={`h-2 w-2 rounded-full ${status.configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`} />
              {status.configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
            </span>
          )}
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.smtp.subtitle")}</p>
        {status && !status.configured && (
          <p className="mb-4 text-sm text-amber-600 dark:text-amber-400">{t("admin.smtp.warning_not_configured")}</p>
        )}
        {msg && <Msg msg={msg} />}
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
          <Field label={t("admin.smtp.password")}>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              placeholder={status?.configured ? t("admin.smtp.password_placeholder_existing") : ""}
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
  "rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400";

const btnDanger =
  "rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950";
