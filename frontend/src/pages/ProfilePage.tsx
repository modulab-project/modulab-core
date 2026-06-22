import type { ReactNode } from "react";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, Avatar } from "../components/AppShell";
import { AuthButton } from "../components/AuthShell";

// "/profile" route, linked from the profile panel AppShell renders on every
// page (header avatar -> "View profile"). Core has no UI of its own for
// editing any of these fields - the IdP (Pocket ID) owns the underlying
// account record, Core only ever reads it via OIDC claims at login time
// (backend/internal/auth.Claims) and mirrors them onto the session. So
// this page is read-only by design: it shows exactly what the IdP told
// Core about this user (name, email, whether the IdP considers that email
// verified) and, instead of pretending to offer edit controls that would
// have nowhere to actually save to, links straight out to the IdP's own
// account-settings page (session.account_settings_url, built by the
// backend's MeHandler from the configured issuer URL) for anyone who
// wants to change something.
//
// Uses AppShell - the same header/footer chrome as Home - rather than a
// standalone screen with its own "Back" button: this is meant to feel like
// a second tab of the same app, reachable straight from the avatar menu,
// not a one-off detour you have to explicitly back out of.
export default function ProfilePage() {
  const { session, loading } = useAuthenticatedSession();

  if (loading || !session) {
    return null;
  }

  const displayName = session.name.trim() || session.email;

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <div className="mb-6 flex items-center gap-4">
          <Avatar session={session} className="h-16 w-16 text-lg" />
          <div>
            <h1 className="text-xl font-semibold">Profile</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Managed by your identity provider - Core only displays what it received at login.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
          <ProfileRow label="Name" value={displayName} />
          <ProfileRow label="Email" value={session.email} />
          <ProfileRow
            label="Email verified"
            value={
              <span
                className={`flex items-center gap-1.5 text-xs font-medium ${
                  session.email_verified
                    ? "text-green-700 dark:text-green-400"
                    : "text-gray-500 dark:text-gray-400"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    session.email_verified ? "bg-green-600" : "bg-gray-400"
                  }`}
                />
                {session.email_verified ? "Verified" : "Not verified"}
              </span>
            }
            last
          />
        </div>

        {session.account_settings_url && (
          <AuthButton
            type="button"
            onClick={() => {
              window.open(session.account_settings_url, "_blank", "noopener,noreferrer");
            }}
            className="mt-6 w-full"
          >
            Manage account in OIDC
          </AuthButton>
        )}
      </div>
    </AppShell>
  );
}

function ProfileRow({
  label,
  value,
  last = false,
}: {
  label: string;
  value: ReactNode;
  last?: boolean;
}) {
  return (
    <div
      className={`flex items-center justify-between px-4 py-3.5 text-sm ${
        last ? "" : "border-b border-gray-100 dark:border-gray-800"
      }`}
    >
      <span className="text-gray-500 dark:text-gray-400">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
