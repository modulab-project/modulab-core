import { useEffect, useState, type KeyboardEvent } from "react";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// Spec section 6.4's "/" route ("Startseite: Begrüßung, Suche, Widgets,
// Schnellzugriff", Consumer+ access). This is the network-wide browser
// homepage every device in the household/org points at - not an admin
// backend - which is why it owns a full-viewport layout (AppShell: sticky
// header/footer, profile/status slide panels) rather than being one more
// scrollable page in the wizard's document flow. AppShell is shared with
// ProfilePage so the two feel like the same app, not a homepage plus a
// bolted-on settings screen.
//
// Deliberately honest about what is real right now: module installs and
// bookmarks (spec sections 4.x / 5.x) have no backend yet (Phase 3 of the
// project roadmap), so there is no tile grid of fake data here, and no
// notification bell either (no SSE/notifications endpoint exists).
export default function Home() {
  const { session, loading } = useAuthenticatedSession();

  // Renders nothing rather than a spinner during the brief getMe() round
  // trip - this page is reached almost exclusively via redirects (from
  // AuthComplete or useAuthenticatedSession's own guard), so there is
  // essentially never a "long" loading state worth designing for.
  if (loading || !session) {
    return null;
  }

  return (
    <AppShell session={session}>
      <Hero name={firstName(session)} />
      <EmptyModulesNotice />
    </AppShell>
  );
}

// --- Hero (clock, greeting, search) -------------------------------------

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 30_000);
    return () => window.clearInterval(id);
  }, []);
  return now;
}

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

function Hero({ name }: { name: string }) {
  const now = useClock();
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const hour = now.getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";

  function handleSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Enter") {
      return;
    }
    const query = e.currentTarget.value.trim();
    if (!query) {
      return;
    }
    window.open(`https://www.google.com/search?q=${encodeURIComponent(query)}`, "_blank", "noopener");
  }

  return (
    <div className="flex flex-col items-center py-9 sm:py-14">
      <p className="m-0 text-[clamp(38px,12vw,64px)] font-semibold leading-none tracking-tight">
        {hours}
        <span className="text-teal-600 dark:text-teal-400">:</span>
        {minutes}
      </p>
      <p className="mt-2 mb-6 text-[13.5px] text-gray-500 dark:text-gray-400">
        {WEEKDAYS[now.getDay()]}, {now.getDate()} {MONTHS[now.getMonth()]} · {greeting}, {name}
      </p>
      <div className="flex h-11 w-full max-w-[440px] items-center gap-2.5 rounded-full border border-teal-600/35 px-[18px]">
        <i className="ti ti-search text-[16px] text-teal-600 dark:text-teal-400" />
        <input
          type="text"
          onKeyDown={handleSearchKeyDown}
          placeholder="Search the web…"
          className="w-full flex-1 bg-transparent text-sm outline-none placeholder:text-gray-400"
        />
      </div>
    </div>
  );
}

// --- Empty modules/bookmarks notice --------------------------------------

// Honest placeholder, not a fake tile grid: module installs and bookmarks
// have no backend yet (Phase 3 of the project roadmap, spec sections 4.x/
// 5.x). This block is the one thing in this file that is meant to be torn
// out and replaced once that API exists - everything else here (hero) is
// already real, and the header/footer chrome lives in AppShell now.
function EmptyModulesNotice() {
  return (
    <div className="mx-auto max-w-xl pb-14">
      <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
        <p className="text-sm font-medium text-gray-700 dark:text-gray-200">No modules installed yet</p>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Module support is part of Phase 3 of the project - once it ships, your installed apps
          and bookmarks will show up here.
        </p>
      </div>
    </div>
  );
}

// First name for the hero greeting - prefers the OIDC-provided display
// name (e.g. PocketID's "Kay Schneider" -> "Kay"), falling back to the
// email's local part when no name claim was set.
function firstName(session: { name: string; email: string }): string {
  const name = session.name.trim();
  if (name) {
    return name.split(/\s+/)[0];
  }
  return session.email.split("@")[0] ?? session.email;
}
