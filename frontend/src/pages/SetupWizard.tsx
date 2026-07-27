import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  setupInit,
  configureOIDC,
  configureGroupPrefix,
  configureSmtp,
  testSmtp,
  completeSetup,
  getHealth,
} from "../lib/api";
import { authErrorKey } from "../lib/authErrors";
import { consumeAuthResult } from "../lib/authResult";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isSuperAdminRole } from "../lib/roles";
import { AuthButton, AuthField, AuthSecondaryButton, AuthShell } from "../components/AuthShell";

// Persisted in sessionStorage, not React state alone, because the
// super-admin login step sends the whole tab away to the IdP and back
// (LoginHandler's redirect) - plain component state would not survive that
// round-trip, but sessionStorage does as long as it's the same tab.
const TOKEN_KEY = "modulab_bootstrap_token";
const STEP_KEY = "modulab_wizard_step";

type StepNumber = 1 | 2 | 3 | 4 | 5 | 6;

function loadStep(): StepNumber {
  const raw = sessionStorage.getItem(STEP_KEY);
  const n = raw ? Number(raw) : 1;
  return (n >= 1 && n <= 6 ? n : 1) as StepNumber;
}

function saveStep(step: StepNumber) {
  sessionStorage.setItem(STEP_KEY, String(step));
}

// Implements the Setup Wizard (spec section 6.5) against the backend's
// /v1/setup/*, /v1/auth/*, and /v1/admin/smtp/* endpoints. 6 steps:
//   1. Bootstrap token
//   2. OIDC credentials
//   3. Group prefix
//   4. Super-admin login
//   5. SMTP (optional, skippable, with test-send)
//   6. Complete
// SMTP is deliberately placed *after* step 4's super-admin login: those
// earlier steps are gated by the bootstrap token (bootstrap.Manager's
// middleware, no session exists yet), but SMTP configuration lives behind
// auth.RequireSuperAdminMiddleware - reusing that same endpoint needs an
// actual session token, which only exists once step 4's OIDC login has
// completed. Skippable and fully editable afterwards from /admin/system/smtp.
//
// Deliberately a single file: each step is a small, self-contained form,
// and splitting them across files would mostly add import boilerplate
// without making any one step easier to follow on its own.
export default function SetupWizard() {
  const { t } = useTranslation();
  const [step, setStep] = useState<StepNumber>(() => loadStep());
  const [bootstrapToken, setBootstrapToken] = useState(
    () => sessionStorage.getItem(TOKEN_KEY) ?? "",
  );
  const [loginRole, setLoginRole] = useState<string | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);
  // Same cross-tab lock as Login.tsx/AdminUsersPage.tsx/ProfilePage.tsx -
  // see lib/useLoginRedirect.ts. If another tab already completed this
  // step's OIDC login (e.g. the wizard was accidentally opened twice),
  // reuse its resolved role instead of running a second round-trip: step 5
  // on success, or the "not a super-admin" message step 4 already shows
  // for the ordinary (single-tab) failure case.
  const { waiting: loginWaiting, startLogin } = useLoginRedirect((session) => {
    setLoginRole(session.role);
    if (isSuperAdminRole(session.role)) {
      goTo(5);
    }
  });

  // null = still checking. The wizard's own step state (loaded from
  // sessionStorage above) has no idea the backend's bootstrap-token gate
  // might already be permanently disabled from a previous run - without
  // this check, completing the wizard once and then simply reloading
  // /setup (or restarting the backend) would show step 1 again and ask for
  // a bootstrap token that no longer exists, since StepComplete clears
  // TOKEN_KEY/STEP_KEY on success. /healthz's setup_completed is the
  // authoritative source of truth here, not anything in sessionStorage.
  const [setupCompleted, setSetupCompleted] = useState<boolean | null>(null);

  useEffect(() => {
    getHealth()
      .then((health) => setSetupCompleted(health.setup_completed))
      .catch(() => setSetupCompleted(false));
  }, []);

  // Runs once on mount - if we just got redirected back from step 4's
  // super-admin login OIDC round trip (via AuthComplete), pick up the
  // result here. AuthComplete only ever sends the browser to /setup while
  // the wizard is still incomplete, so unlike before /login existed, this
  // no longer needs to handle an ordinary post-setup login landing here.
  useEffect(() => {
    const result = consumeAuthResult();
    if (!result) {
      return;
    }
    if (result.error) {
      // Runs exactly once on mount ([] deps) to read a one-shot stashed
      // result from an external store (consumeAuthResult consumes/clears
      // the entry, so this can never re-fire or cascade) - same shape as
      // Login.tsx's mount effect, see its comment for the full rationale.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setLoginError(authErrorKey(result.error));
      return;
    }
    if (result.role) {
      setLoginRole(result.role);
      if (isSuperAdminRole(result.role)) {
        goTo(5);
      }
    }
  }, []);

  function goTo(next: StepNumber) {
    setStep(next);
    saveStep(next);
  }

  function persistToken(token: string) {
    setBootstrapToken(token);
    sessionStorage.setItem(TOKEN_KEY, token);
  }

  if (setupCompleted === null) {
    return null;
  }

  if (setupCompleted) {
    // Setup is done - /setup has nothing left to do for anyone, wizard or
    // ordinary user. /login (spec section 6.4) is the canonical entry
    // point now; this only triggers for someone hitting /setup directly
    // by URL after the fact, or the wildcard route falling through to it.
    return <Navigate to="/login" replace />;
  }

  return (
    <AuthShell title={t("setup.title")} subtitle={t("setup.step_of", { step })}>
      {step === 1 && (
        <StepBootstrapToken
          initialValue={bootstrapToken}
          onSuccess={(token) => {
            persistToken(token);
            goTo(2);
          }}
        />
      )}
      {step === 2 && (
        <StepOIDCCredentials
          bootstrapToken={bootstrapToken}
          onSuccess={() => goTo(3)}
          onBack={() => goTo(1)}
        />
      )}
      {step === 3 && (
        <StepGroupPrefix
          bootstrapToken={bootstrapToken}
          onSuccess={() => goTo(4)}
          onBack={() => goTo(2)}
        />
      )}
      {step === 4 && (
        <StepSuperAdminLogin
          role={loginRole}
          error={loginError ? t(loginError) : null}
          waiting={loginWaiting}
          onRetry={() => {
            setLoginError(null);
            setLoginRole(null);
            startLogin();
          }}
        />
      )}
      {step === 5 && <StepSMTP onDone={() => goTo(6)} />}
      {step === 6 && <StepComplete bootstrapToken={bootstrapToken} />}
    </AuthShell>
  );
}

// --- Step 1: Bootstrap token ----------------------------------------------

function StepBootstrapToken({
  initialValue,
  onSuccess,
}: {
  initialValue: string;
  onSuccess: (token: string) => void;
}) {
  const { t } = useTranslation();
  const [token, setToken] = useState(initialValue);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await setupInit(token.trim());
      onSuccess(token.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : t("setup.unknown_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        {t("setup.step1.hint")}
      </p>
      <AuthField
        label={t("setup.step1.label")}
        id="bootstrap-token"
        value={token}
        onChange={setToken}
        placeholder="mlab_..."
        required
      />
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <AuthButton type="submit" disabled={busy || token.trim() === ""} className="w-full">
        {busy ? t("setup.step1.checking") : t("setup.step1.next")}
      </AuthButton>
    </form>
  );
}

// --- Step 2: OIDC credentials ----------------------------------------------

function StepOIDCCredentials({
  bootstrapToken,
  onSuccess,
  onBack,
}: {
  bootstrapToken: string;
  onSuccess: () => void;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await configureOIDC(bootstrapToken, {
        issuer_url: issuerUrl.trim(),
        client_id: clientId.trim(),
        client_secret: clientSecret,
      });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("setup.unknown_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        {t("setup.step2.hint")}
      </p>
      <AuthField
        label={t("setup.step2.issuer_url")}
        id="issuer-url"
        value={issuerUrl}
        onChange={setIssuerUrl}
        placeholder="https://auth.example.com"
        required
      />
      <AuthField label={t("setup.step2.client_id")} id="client-id" value={clientId} onChange={setClientId} required />
      <AuthField
        label={t("setup.step2.client_secret")}
        id="client-secret"
        value={clientSecret}
        onChange={setClientSecret}
        type="password"
        required
      />
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex gap-2">
        <AuthSecondaryButton onClick={onBack} type="button" className="flex-1">
          {t("setup.step2.back")}
        </AuthSecondaryButton>
        <AuthButton type="submit" disabled={busy} className="flex-1">
          {busy ? t("setup.step2.saving") : t("setup.step2.next")}
        </AuthButton>
      </div>
    </form>
  );
}

// --- Step 3: group prefix ---------------------------------------------------

function StepGroupPrefix({
  bootstrapToken,
  onSuccess,
  onBack,
}: {
  bootstrapToken: string;
  onSuccess: () => void;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const [prefix, setPrefix] = useState("modulab_");
  const [groups, setGroups] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const status = await configureGroupPrefix(bootstrapToken, prefix.trim());
      setGroups(status.groups ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("setup.unknown_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="space-y-4">
        <AuthField
          label={t("setup.step3.group_prefix")}
          id="group-prefix"
          value={prefix}
          onChange={setPrefix}
          placeholder="modulab_"
          required
        />
        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <div className="flex gap-2">
          <AuthSecondaryButton onClick={onBack} type="button" className="flex-1">
            {t("setup.step3.back")}
          </AuthSecondaryButton>
          <AuthButton type="submit" disabled={busy || prefix.trim() === ""} className="flex-1">
            {busy ? t("setup.step3.saving") : t("setup.step3.save")}
          </AuthButton>
        </div>
      </form>

      {groups && (
        <div className="rounded-md border border-gray-200 bg-gray-50 p-4 text-sm dark:border-gray-700 dark:bg-gray-800">
          <p className="mb-2 font-medium text-gray-700 dark:text-gray-200">
            {t("setup.step3.groups_intro")}
          </p>
          <ul className="list-disc space-y-1 pl-5 font-mono text-gray-600 dark:text-gray-400">
            {groups.map((g) => (
              <li key={g} className="break-all">{g}</li>
            ))}
          </ul>
          <AuthButton onClick={onSuccess} type="button" className="mt-4">
            {t("setup.step3.continue")}
          </AuthButton>
        </div>
      )}
    </div>
  );
}

// --- Step 4: Super-Admin login ----------------------------------------------

function StepSuperAdminLogin({
  role,
  error,
  waiting,
  onRetry,
}: {
  role: string | null;
  error: string | null;
  // True while another tab already holds the login lock (see
  // lib/useLoginRedirect.ts) - i.e. someone already started this exact
  // step's OIDC login elsewhere. Disables the button rather than letting a
  // second click fire a second, redundant round-trip.
  waiting: boolean;
  onRetry: () => void;
}) {
  const { t } = useTranslation();
  const notSuperAdmin = role !== null && !isSuperAdminRole(role);
  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        {t("setup.step4.hint")}
      </p>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      {notSuperAdmin && (
        <p className="text-sm text-red-600 dark:text-red-400">
          {t("setup.step4.not_super_admin")}
        </p>
      )}
      <AuthButton onClick={onRetry} type="button" disabled={waiting} className="w-full">
        {waiting ? t("login.waiting_other_tab") : t("setup.step4.login_button")}
      </AuthButton>
    </div>
  );
}

// --- Step 5: SMTP (optional, skippable, with test-send) --------------------

// Unlike every earlier step, this one authenticates with the httpOnly
// session cookie step 4's super-admin login set (see
// backend/internal/auth/handlers.go's setSessionCookie), not the bootstrap
// token - see the top-of-file comment for why. It calls the same
// configureSmtp() the standalone /admin/system/smtp page uses, so anything
// saved or skipped here is just as visible and editable there afterwards.
// The test-send button calls POST /v1/admin/smtp/test with the current form
// values (not yet saved), so the operator can verify connectivity before
// committing the configuration.
function StepSMTP({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("465");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [encryption, setEncryption] = useState("tls");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testAddress, setTestAddress] = useState("");
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setError(t("setup.step5.validation_error"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await configureSmtp({
        host: host.trim(),
        port: parsedPort,
        username: username.trim(),
        password,
        from_address: fromAddress.trim(),
        encryption,
      });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("setup.unknown_error"));
    } finally {
      setBusy(false);
    }
  }

  async function sendTest(e: FormEvent) {
    e.preventDefault();
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setTestResult({ ok: false, message: t("setup.step5.validation_error") });
      return;
    }
    if (!testAddress.trim()) {
      setTestResult({ ok: false, message: t("setup.step5.test_address_required") });
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
      setTestResult({ ok: true, message: t("setup.step5.test_ok") });
    } catch (err) {
      setTestResult({ ok: false, message: err instanceof Error ? err.message : t("setup.unknown_error") });
    } finally {
      setTestBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        {t("setup.step5.hint")}
      </p>
      <AuthField label={t("setup.step5.host")} id="smtp-host" value={host} onChange={setHost} placeholder="mail.example.com" />
      <AuthField label={t("setup.step5.port")} id="smtp-port" value={port} onChange={setPort} />
      <AuthField
        label={t("setup.step5.username")}
        id="smtp-username"
        value={username}
        onChange={setUsername}
        placeholder={t("admin.smtp.username_placeholder")}
      />
      <AuthField
        label={t("setup.step5.password")}
        id="smtp-password"
        value={password}
        onChange={setPassword}
        type="password"
      />
      <AuthField
        label={t("setup.step5.from_address")}
        id="smtp-from"
        value={fromAddress}
        onChange={setFromAddress}
        type="email"
        placeholder="modulab@example.com"
      />
      <div>
        <label htmlFor="smtp-encryption" className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
          {t("setup.step5.encryption")}
        </label>
        <select
          id="smtp-encryption"
          value={encryption}
          onChange={(e) => setEncryption(e.target.value)}
          className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        >
          <option value="none">{t("setup.step5.enc_none")}</option>
          <option value="starttls">{t("setup.step5.enc_starttls")}</option>
          <option value="tls">{t("setup.step5.enc_tls")}</option>
        </select>
      </div>

      {/* Test-send row — submits via sendTest, not the main form's submit */}
      <div className="rounded-md border border-gray-200 bg-gray-50 p-3 dark:border-gray-700 dark:bg-gray-800/50">
        <p className="mb-2 text-xs font-medium text-gray-600 dark:text-gray-400">
          {t("setup.step5.test_hint")}
        </p>
        <div className="flex gap-2">
          <input
            type="email"
            value={testAddress}
            onChange={(e) => setTestAddress(e.target.value)}
            placeholder={t("setup.step5.test_address_placeholder")}
            className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
          />
          <AuthSecondaryButton
            onClick={sendTest}
            type="button"
            disabled={testBusy || testAddress.trim() === ""}
          >
            {testBusy ? t("setup.step5.test_sending") : t("setup.step5.test_button")}
          </AuthSecondaryButton>
        </div>
        {testResult && (
          <p className={`mt-2 text-xs ${testResult.ok ? "text-teal-600 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
            {testResult.message}
          </p>
        )}
      </div>

      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex gap-2">
        <AuthSecondaryButton onClick={onDone} type="button" disabled={busy} className="flex-1">
          {t("setup.step5.skip")}
        </AuthSecondaryButton>
        <AuthButton type="submit" disabled={busy} className="flex-1">
          {busy ? t("setup.step5.saving") : t("setup.step5.save_continue")}
        </AuthButton>
      </div>
    </form>
  );
}

// --- Step 6: completion -----------------------------------------------------

function StepComplete({ bootstrapToken }: { bootstrapToken: string }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function finish() {
    setBusy(true);
    setError(null);
    try {
      const res = await completeSetup(bootstrapToken);
      if (res.completed) {
        setDone(true);
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(STEP_KEY);
      } else {
        setError(t("setup.step6.missing", { items: (res.missing ?? []).join(", ") }));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t("setup.unknown_error"));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return <StepCompleteDone />;
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        {t("setup.step6.hint")}
      </p>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <AuthButton onClick={finish} disabled={busy} type="button" className="w-full">
        {busy ? t("setup.step6.finishing") : t("setup.step6.complete_button")}
      </AuthButton>
    </div>
  );
}

// The super-admin login in step 4 already set the session cookie (see
// backend/internal/auth/handlers.go's setSessionCookie, applied on
// CallbackHandler's redirect), so there is no need to send them through
// /login again - straight to / works immediately.
function StepCompleteDone() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <div className="space-y-4">
      <p className="text-sm font-medium text-teal-700 dark:text-teal-400">
        {t("setup.step6.done_message")}
      </p>
      <AuthButton type="button" onClick={() => navigate("/")} className="w-full">
        {t("setup.step6.done_button")}
      </AuthButton>
    </div>
  );
}
