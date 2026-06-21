import { useEffect, useState, type FormEvent } from "react";
import {
  setupInit,
  configureOIDC,
  configureDNSChallenge,
  configureGroupPrefix,
  completeSetup,
  loginRedirectUrl,
  getHealth,
} from "../lib/api";
import { consumeAuthResult } from "./AuthComplete";

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
// /v1/setup/* and /v1/auth/* endpoints, in 6 steps rather than the spec's 7:
// the spec's step 2 ("choose your OIDC provider") was dropped on 2026-06-21
// because it was purely informational - ModuLab Core talks to every
// standard OIDC provider identically, so the dropdown changed no behavior
// at all and just added a click. The wizard now goes straight from the
// bootstrap token into entering OIDC credentials.
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

  // Runs once on mount - if we just got redirected back from the
  // super-admin login step's OIDC round-trip (via AuthComplete), pick up
  // the result here. This also fires for an ordinary post-setup login (the
  // wizard is done, the user just clicked "Log in with OIDC" below), which
  // is why it does not assume it's still inside the wizard.
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
    return (
      <div className="mx-auto max-w-xl px-4 py-10">
        <h1 className="mb-1 text-2xl font-semibold text-gray-900">ModuLab Core</h1>
        <AlreadySetUp
          role={loginRole}
          error={loginError}
          onRetry={() => {
            setLoginError(null);
            setLoginRole(null);
            window.location.href = loginRedirectUrl();
          }}
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-xl px-4 py-10">
      <h1 className="mb-1 text-2xl font-semibold text-gray-900">ModuLab Core – Initial Setup</h1>
      <p className="mb-8 text-sm text-gray-500">Step {step} of 6</p>

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
      {step === 6 && <StepComplete bootstrapToken={bootstrapToken} />}
    </div>
  );
}

// Mirrors the error codes CallbackHandler's redirectToFrontend calls use in
// handlers.go - keep these two in sync.
function describeAuthError(code: string): string {
  switch (code) {
    case "missing_state_or_code":
      return "The login attempt was incomplete. Please try again.";
    case "invalid_or_expired_state":
      return "The login attempt expired. Please try again.";
    case "provider_unavailable":
      return "OIDC is not fully configured yet.";
    case "exchange_failed":
      return "Login with the identity provider failed.";
    case "group_prefix_unavailable":
      return "The group prefix is not configured yet.";
    default:
      return "An unexpected error occurred during login.";
  }
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
      <p className="text-sm text-gray-600">
        You'll find the bootstrap token once in ModuLab Core's startup log.
      </p>
      <Field
        label="Bootstrap Token"
        id="bootstrap-token"
        value={token}
        onChange={setToken}
        placeholder="mlab_..."
        required
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <button
        type="submit"
        disabled={busy || token.trim() === ""}
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {busy ? "Checking…" : "Next"}
      </button>
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
      <p className="text-sm text-gray-600">
        Enter your OIDC provider's details. ModuLab Core talks to any standard OIDC provider the
        same way (Pocket ID, Authentik, Keycloak, Authelia, or anything else that speaks OIDC).
      </p>
      <Field
        label="Issuer URL"
        id="issuer-url"
        value={issuerUrl}
        onChange={setIssuerUrl}
        placeholder="https://auth.example.com"
        required
      />
      <Field label="Client ID" id="client-id" value={clientId} onChange={setClientId} required />
      <Field
        label="Client Secret"
        id="client-secret"
        value={clientSecret}
        onChange={setClientSecret}
        type="password"
        required
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="flex gap-2">
        <button
          onClick={onBack}
          type="button"
          className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Back
        </button>
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {busy ? "Saving…" : "Next"}
        </button>
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
      <p className="text-sm text-gray-600">
        Required for automatic TLS certificates via Traefik/Let&apos;s Encrypt.
      </p>
      <div>
        <label htmlFor="dns-provider" className="mb-1 block text-sm font-medium text-gray-700">
          DNS Provider
        </label>
        <select
          id="dns-provider"
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          {DNS_PROVIDER_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </div>
      <Field
        label="API Credentials"
        id="dns-credentials"
        value={credentials}
        onChange={setCredentials}
        type="password"
        placeholder="e.g. API token"
        required
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="flex gap-2">
        <button
          onClick={onBack}
          type="button"
          className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Back
        </button>
        <button
          type="submit"
          disabled={busy || credentials.trim() === ""}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {busy ? "Saving…" : "Next"}
        </button>
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
        <Field
          label="Group Prefix"
          id="group-prefix"
          value={prefix}
          onChange={setPrefix}
          placeholder="modulab_"
          required
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <div className="flex gap-2">
          <button
            onClick={onBack}
            type="button"
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            Back
          </button>
          <button
            type="submit"
            disabled={busy || prefix.trim() === ""}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </form>

      {groups && (
        <div className="rounded-md border border-gray-200 bg-gray-50 p-4 text-sm">
          <p className="mb-2 font-medium text-gray-700">
            Create these three groups in your OIDC provider and assign your account to the
            super-admin group before continuing:
          </p>
          <ul className="list-disc space-y-1 pl-5 font-mono text-gray-600">
            {groups.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
          <button
            onClick={onSuccess}
            type="button"
            className="mt-4 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            Continue to login
          </button>
        </div>
      )}
    </div>
  );
}

// --- Already set up (setup_completed from /healthz) -------------------------

// Shown instead of the wizard once the backend reports the wizard already
// completed in a previous run. There is no login screen or dashboard yet
// (that's later Phase 2 work, per the project roadmap), so this is
// deliberately minimal: a single "Log in with OIDC" button reusing the same
// /v1/auth/login redirect the wizard's own login step uses, plus whatever
// result comes back from it.
function AlreadySetUp({
  role,
  error,
  onRetry,
}: {
  role: string | null;
  error: string | null;
  onRetry: () => void;
}) {
  if (role) {
    return (
      <div className="space-y-2">
        <p className="text-sm font-medium text-green-700">Logged in as {role}.</p>
        <p className="text-sm text-gray-500">
          There's no dashboard yet - that's still being built.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600">
        Setup is already complete. Log in with your OIDC account to continue.
      </p>
      {error && <p className="text-sm text-red-600">{error}</p>}
      <button
        onClick={onRetry}
        type="button"
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
      >
        Log in with OIDC
      </button>
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
      <p className="text-sm text-gray-600">
        Log in now with your OIDC account to bind it as super-admin.
      </p>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {notSuperAdmin && (
        <p className="text-sm text-red-600">
          This user is not a member of the super-admin group. Please assign it in your OIDC
          provider and log in again.
        </p>
      )}
      <button
        onClick={onRetry}
        type="button"
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
      >
        Log in with OIDC
      </button>
    </div>
  );
}

// --- Step 6: completion -----------------------------------------------------

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
    return (
      <p className="text-sm font-medium text-green-700">
        Setup complete. ModuLab Core is now in normal operation.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600">Last step: permanently disable the bootstrap token.</p>
      {error && <p className="text-sm text-red-600">{error}</p>}
      <button
        onClick={finish}
        disabled={busy}
        type="button"
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {busy ? "Finishing…" : "Complete setup"}
      </button>
    </div>
  );
}

// --- Shared field component --------------------------------------------------

function Field({
  label,
  id,
  value,
  onChange,
  type = "text",
  placeholder,
  required,
}: {
  label: string;
  id: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-gray-700">
        {label}
      </label>
      <input
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
      />
    </div>
  );
}
