import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
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
      .catch(() => setError("Could not load SMTP settings."));
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
      setError("Host, port, and from address are all required.");
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
      const message = err instanceof Error ? err.message : "Saving failed.";
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
    if (!window.confirm("Remove the SMTP configuration? Account notification emails will stop going out until it is set up again.")) {
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
      const message = err instanceof Error ? err.message : "Removing the configuration failed.";
      setError(message);
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <h1 className="mb-1 text-xl font-semibold">SMTP</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          Outbound mail for account notifications (approved, locked, unlocked). Compatible with any
          self-hosted relay - Postfix, Mailcow, Stalwart, or similar.
        </p>

        {status && !status.configured && (
          <p className="mb-4 text-sm text-amber-600 dark:text-amber-400">
            Not configured yet - queued notifications are dropped until this is set up.
          </p>
        )}
        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {savedAt && !error && (
          <p className="mb-4 text-sm text-green-700 dark:text-green-400">Saved.</p>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="Host">
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="mail.example.com"
              className={inputClass}
            />
          </Field>
          <Field label="Port">
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className={inputClass}
            />
          </Field>
          <Field label="Username">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="leave empty for an unauthenticated relay"
              className={inputClass}
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={status?.configured ? "leave empty to keep using no/empty password" : ""}
              className={inputClass}
            />
          </Field>
          <Field label="From address">
            <input
              type="email"
              value={fromAddress}
              onChange={(e) => setFromAddress(e.target.value)}
              placeholder="modulab@example.com"
              className={inputClass}
            />
          </Field>
          <Field label="Encryption">
            <select
              value={encryption}
              onChange={(e) => setEncryption(e.target.value)}
              className={inputClass}
            >
              <option value="none">None</option>
              <option value="starttls">STARTTLS (e.g. port 587)</option>
              <option value="tls">SSL/TLS (e.g. port 465)</option>
            </select>
          </Field>

          <button
            type="submit"
            disabled={saving}
            className="w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400"
          >
            {saving ? "Saving…" : "Save"}
          </button>

          {status?.configured && (
            <button
              type="button"
              disabled={removing}
              onClick={handleRemove}
              className="w-full rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
            >
              {removing ? "Removing…" : "Remove configuration"}
            </button>
          )}
        </form>
      </div>
    </AppShell>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
    </label>
  );
}
