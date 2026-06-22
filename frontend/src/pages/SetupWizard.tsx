import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import {
  setupInit,
  configureOIDC,
  configureDNSChallenge,
  configureGroupPrefix,
  configureSmtp,
  completeSetup,
  loginRedirectUrl,
  getHealth,
} from "../lib/api";
import { describeAuthError } from "../lib/authErrors";
import { consumeAuthResult } from "./AuthComplete";
import { getSessionToken } from "../lib/session";
import { AuthButton, AuthField, AuthSecondaryButton, AuthShell } from "../components/AuthShell";

// Persisted in sessionStorage, not React state alone, because the
// super-admin login step sends the whole tab away to the IdP and back
// (LoginHandler's redirect) - plain component state would not survive that
// round-trip, but sessionStorage does as long as it's the same tab.
const TOKEN_KEY = "modulab_bootstrap_token";
const STEP_KEY = "modulab_wizard_step";

type StepNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7;

function loadStep(): StepNumber {
  const raw = sessionStorage.getItem(STEP_KEY);
  const n = raw ? Number(raw) : 1;
  return (n >= 1 && n <= 7 ? n : 1) as StepNumber;
}

function saveStep(step: StepNumber) {
  sessionStorage.setItem(STEP_KEY, String(step));
}

// Implements the Setup Wizard (spec section 6.5) against the backend's
// /v1/setup/*, /v1/auth/*, and /v1/admin/smtp/* endpoints. 7 steps today,
// same number as the original spec but for a different reason: the spec's
// own step 2 ("choose your OIDC provider") was dropped on 2026-06-21 -
// ModuLab Core talks to every standard OIDC provider identically, so the
// dropdown changed no behavior at all and just added a click - which took
// the wizard down to 6 steps for a while, until step 6 below (SMTP) was
// added back on the user's request, landing back at 7.
// SMTP is deliberately placed *after* step 5's super-admin login rather
// than alongside OIDC/DNS-challenge/group-prefix: those three are gated by
// the bootstrap token (bootstrap.Manager's middleware, no session exists
// yet), but SMTP configuration lives behind auth.RequireSuperAdminMiddleware
// (see setup/smtp.go's doc comment on why it is admin-panel-only, not
// wizard-only) - reusing that same endpoint here, instead of adding a
// second bootstrap-token-gated copy, needs an actual session token, which
// only exists once step 5's OIDC login has completed. Skippable - and,
// unlike DNS-challenge, still fully editable afterwards from /admin/smtp
// (AdminSmtpPage.tsx) any time, by any super-admin, not just during setup.
//
// Deliberately a single file: each step is a small, self-contained form,
// and splitting them across files would mostly add import boilerplate
// without making any one step easier to follow on its own.
export default function SetupWizard() {
  const [step, setStep] = useState<StepNumber>(() => loadStep());
  const [bootstrapToken, setBootstrapToken] = useState(
    () => sessionStorage.getItem(TOKEN_KEY) ?? "",
  );
  const [loginRole, setLoginRole] = useState<string | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);

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

  // Runs once on mount - if we just got redirected back from step 5's
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
      setLoginError(describeAuthError(result.error));
      return;
    }
    if (result.role) {
      setLoginRole(result.role);
      if (result.role === "super-admin") {
        goTo(6);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    <AuthShell title="ModuLab Core – Initial Setup" subtitle={`Step ${step} of 7`}>
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
        <StepDNSChallenge
          bootstrapToken={bootstrapToken}
          onSuccess={() => goTo(4)}
          onBack={() => goTo(2)}
        />
      )}
      {step === 4 && (
        <StepGroupPrefix
          bootstrapToken={bootstrapToken}
          onSuccess={() => goTo(5)}
          onBack={() => goTo(3)}
        />
      )}
      {step === 5 && (
        <StepSuperAdminLogin
          role={loginRole}
          error={loginError}
          onRetry={() => {
            setLoginError(null);
            setLoginRole(null);
            window.location.href = loginRedirectUrl();
          }}
        />
      )}
      {step === 6 && <StepSMTP onDone={() => goTo(7)} />}
      {step === 7 && <StepComplete bootstrapToken={bootstrapToken} />}
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
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        You'll find the bootstrap token once in ModuLab Core's startup log.
      </p>
      <AuthField
        label="Bootstrap Token"
        id="bootstrap-token"
        value={token}
        onChange={setToken}
        placeholder="mlab_..."
        required
      />
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <AuthButton type="submit" disabled={busy || token.trim() === ""} className="w-full">
        {busy ? "Checking…" : "Next"}
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
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Enter your OIDC provider's details. ModuLab Core talks to any standard OIDC provider the
        same way (Pocket ID, Authentik, Keycloak, Authelia, or anything else that speaks OIDC).
      </p>
      <AuthField
        label="Issuer URL"
        id="issuer-url"
        value={issuerUrl}
        onChange={setIssuerUrl}
        placeholder="https://auth.example.com"
        required
      />
      <AuthField label="Client ID" id="client-id" value={clientId} onChange={setClientId} required />
      <AuthField
        label="Client Secret"
        id="client-secret"
        value={clientSecret}
        onChange={setClientSecret}
        type="password"
        required
      />
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex gap-2">
        <AuthSecondaryButton onClick={onBack} type="button" className="flex-1">
          Back
        </AuthSecondaryButton>
        <AuthButton type="submit" disabled={busy} className="flex-1">
          {busy ? "Saving…" : "Next"}
        </AuthButton>
      </div>
    </form>
  );
}

// --- Step 3: DNS-challenge provider (mandatory, no skip) -------------------

const DNS_PROVIDER_OPTIONS = ["Cloudflare", "Route53", "DigitalOcean", "Hetzner"];

function StepDNSChallenge({
  bootstrapToken,
  onSuccess,
  onBack,
}: {
  bootstrapToken: string;
  onSuccess: () => void;
  onBack: () => void;
}) {
  const [provider, setProvider] = useState(DNS_PROVIDER_OPTIONS[0]);
  const [credentials, setCredentials] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await configureDNSChallenge(bootstrapToken, { provider, credentials });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Required for automatic TLS certificates via Traefik/Let&apos;s Encrypt.
      </p>
      <div>
        <label
          htmlFor="dns-provider"
          className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300"
        >
          DNS Provider
        </label>
        <select
          id="dns-provider"
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        >
          {DNS_PROVIDER_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </div>
      <AuthField
        label="API Credentials"
        id="dns-credentials"
        value={credentials}
        onChange={setCredentials}
        type="password"
        placeholder="e.g. API token"
        required
      />
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex gap-2">
        <AuthSecondaryButton onClick={onBack} type="button" className="flex-1">
          Back
        </AuthSecondaryButton>
        <AuthButton type="submit" disabled={busy || credentials.trim() === ""} className="flex-1">
          {busy ? "Saving…" : "Next"}
        </AuthButton>
      </div>
    </form>
  );
}

// --- Step 4: group prefix ---------------------------------------------------

function StepGroupPrefix({
  bootstrapToken,
  onSuccess,
  onBack,
}: {
  bootstrapToken: string;
  onSuccess: () => void;
  onBack: () => void;
}) {
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
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="space-y-4">
        <AuthField
          label="Group Prefix"
          id="group-prefix"
          value={prefix}
          onChange={setPrefix}
          placeholder="modulab_"
          required
        />
        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <div className="flex gap-2">
          <AuthSecondaryButton onClick={onBack} type="button" className="flex-1">
            Back
          </AuthSecondaryButton>
          <AuthButton type="submit" disabled={busy || prefix.trim() === ""} className="flex-1">
            {busy ? "Saving…" : "Save"}
          </AuthButton>
        </div>
      </form>

      {groups && (
        <div className="rounded-md border border-gray-200 bg-gray-50 p-4 text-sm dark:border-gray-700 dark:bg-gray-800">
          <p className="mb-2 font-medium text-gray-700 dark:text-gray-200">
            Create these three groups in your OIDC provider and assign your account to the
            super-admin group before continuing:
          </p>
          <ul className="list-disc space-y-1 pl-5 font-mono text-gray-600 dark:text-gray-400">
            {groups.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
          <AuthButton onClick={onSuccess} type="button" className="mt-4">
            Continue to login
          </AuthButton>
        </div>
      )}
    </div>
  );
}

// --- Step 5: Super-Admin login ----------------------------------------------

function StepSuperAdminLogin({
  role,
  error,
  onRetry,
}: {
  role: string | null;
  error: string | null;
  onRetry: () => void;
}) {
  const notSuperAdmin = role !== null && role !== "super-admin";
  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Log in now with your OIDC account to bind it as super-admin.
      </p>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      {notSuperAdmin && (
        <p className="text-sm text-red-600 dark:text-red-400">
          This user is not a member of the super-admin group. Please assign it in your OIDC
          provider and log in again.
        </p>
      )}
      <AuthButton onClick={onRetry} type="button" className="w-full">
        Log in with OIDC
      </AuthButton>
    </div>
  );
}

// --- Step 6: SMTP (optional, skippable) -------------------------------------

// Unlike every earlier step, this one authenticates with the session
// token from step 5's super-admin login (getSessionToken()), not the
// bootstrap token - see the top-of-file comment for why. It calls the same
// configureSmtp() the standalone /admin/smtp page (AdminSmtpPage.tsx)
// uses, so anything saved or skipped here is just as visible and just as
// editable from there afterwards - this step has no state of its own
// beyond what that endpoint already persists.
function StepSMTP({ onDone }: { onDone: () => void }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("587");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [useTLS, setUseTLS] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) {
      // Should not happen - step 5 always persists one before advancing
      // here - but skip ahead rather than get the operator stuck on a
      // step that cannot possibly succeed without one.
      onDone();
      return;
    }
    const parsedPort = parseInt(port, 10);
    if (!host.trim() || !fromAddress.trim() || Number.isNaN(parsedPort) || parsedPort <= 0) {
      setError("Host, port, and from address are all required - or use Skip below.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await configureSmtp(token, {
        host: host.trim(),
        port: parsedPort,
        username: username.trim(),
        password,
        from_address: fromAddress.trim(),
        use_tls: useTLS,
      });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Optional: outbound mail for account notifications (approved, locked, unlocked). Skip this
        and set it up later from Admin → SMTP any time, or fill it in now.
      </p>
      <AuthField label="Host" id="smtp-host" value={host} onChange={setHost} placeholder="mail.example.com" />
      <AuthField label="Port" id="smtp-port" value={port} onChange={setPort} />
      <AuthField
        label="Username"
        id="smtp-username"
        value={username}
        onChange={setUsername}
        placeholder="leave empty for an unauthenticated relay"
      />
      <AuthField
        label="Password"
        id="smtp-password"
        value={password}
        onChange={setPassword}
        type="password"
      />
      <AuthField
        label="From address"
        id="smtp-from"
        value={fromAddress}
        onChange={setFromAddress}
        type="email"
        placeholder="modulab@example.com"
      />
      <label className="flex items-center gap-2.5 text-sm text-gray-700 dark:text-gray-300">
        <input
          type="checkbox"
          checked={useTLS}
          onChange={(e) => setUseTLS(e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-teal-600 focus:ring-teal-500 dark:border-gray-700"
        />
        Use STARTTLS
      </label>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex gap-2">
        <AuthSecondaryButton onClick={onDone} type="button" disabled={busy} className="flex-1">
          Skip
        </AuthSecondaryButton>
        <AuthButton type="submit" disabled={busy} className="flex-1">
          {busy ? "Saving…" : "Save & continue"}
        </AuthButton>
      </div>
    </form>
  );
}

// --- Step 7: completion -----------------------------------------------------

function StepComplete({ bootstrapToken }: { bootstrapToken: string }) {
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
        setError(`Not yet complete, missing: ${(res.missing ?? []).join(", ")}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
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
        Last step: permanently disable the bootstrap token.
      </p>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <AuthButton onClick={finish} disabled={busy} type="button" className="w-full">
        {busy ? "Finishing…" : "Complete setup"}
      </AuthButton>
    </div>
  );
}

// The super-admin login in step 5 already persisted a session token (see
// AuthComplete.tsx's storeSessionToken call), so there is no need to send
// them through /login again - straight to / works immediately.
function StepCompleteDone() {
  const navigate = useNavigate();
  return (
    <div className="space-y-4">
      <p className="text-sm font-medium text-green-700 dark:text-green-400">
        Setup complete. ModuLab Core is now in normal operation.
      </p>
      <AuthButton type="button" onClick={() => navigate("/")} className="w-full">
        Continue to ModuLab
      </AuthButton>
    </div>
  );
}
