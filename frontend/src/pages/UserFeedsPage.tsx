import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "../components/AppShell";
import { useAuthenticatedSession } from "../lib/useSession";
import { listFeeds, setFeedSubscription, type Feed } from "../lib/api";
import { USER_FEEDS_QUERY_KEY } from "../lib/queryKeys";

// /user/feeds — lets every approved user manage their feed subscriptions.
// Mirrors the FeedsPanel slide panel on the homepage but as a standalone
// page so it's reachable from the profile panel on any route.
export default function UserFeedsPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const queryClient = useQueryClient();
  const [toggling, setToggling] = useState<number | null>(null);
  const [toggleError, setToggleError] = useState(false);

  const {
    data: feeds = [],
    isLoading: fetching,
    isError: loadError,
  } = useQuery({
    queryKey: USER_FEEDS_QUERY_KEY,
    queryFn: async () => (await listFeeds()) ?? [],
    enabled: !loading && !!session,
  });

  async function handleToggle(feed: Feed) {
    if (toggling !== null) return;
    const next = !feed.enabled;
    setToggling(feed.id);
    setToggleError(false);
    queryClient.setQueryData<Feed[]>(USER_FEEDS_QUERY_KEY, (prev) =>
      (prev ?? []).map((f) => (f.id === feed.id ? { ...f, enabled: next } : f)),
    );
    try {
      await setFeedSubscription(feed.id, next);
    } catch {
      // Revert the optimistic toggle, and say so - a toggle that visibly
      // flips back is confusing without an explanation.
      queryClient.setQueryData<Feed[]>(USER_FEEDS_QUERY_KEY, (prev) =>
        (prev ?? []).map((f) => (f.id === feed.id ? { ...f, enabled: feed.enabled } : f)),
      );
      setToggleError(true);
    } finally {
      setToggling(null);
    }
  }

  if (loading || !session) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-3xl px-4 py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("user.feeds.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("user.feeds.subtitle")}
        </p>

        {(loadError || toggleError) && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">
            {loadError ? t("user.feeds.load_error") : t("user.feeds.toggle_error")}
          </p>
        )}

        {fetching ? (
          <div className="flex flex-col gap-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse h-14 rounded-xl bg-gray-100 dark:bg-gray-800"
              />
            ))}
          </div>
        ) : feeds.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {t("user.feeds.empty")}
            </p>
          </div>
        ) : (
          <div className="flex flex-col divide-y divide-gray-100 rounded-2xl border border-gray-100 dark:divide-gray-800 dark:border-gray-800">
            {feeds.map((feed) => (
              <div
                key={feed.id}
                className="flex items-center gap-3 px-4 py-3.5"
              >
                <i className="ti ti-rss shrink-0 text-[15px] text-teal-600 dark:text-teal-400" />
                <div className="min-w-0 flex-1">
                  <p className="break-words text-sm font-medium">{feed.label}</p>
                  <p className="break-all text-xs text-gray-500 dark:text-gray-400">{feed.url}</p>
                </div>
                <button
                  type="button"
                  aria-label={feed.enabled ? t("home.feeds.disable_label", { name: feed.label }) : t("home.feeds.enable_label", { name: feed.label })}
                  disabled={toggling === feed.id}
                  onClick={() => handleToggle(feed)}
                  className={`relative h-[22px] w-10 flex-none rounded-full border transition-colors disabled:opacity-50 ${
                    feed.enabled
                      ? "border-teal-600 bg-teal-600"
                      : "border-gray-300 bg-gray-100 dark:border-gray-600 dark:bg-gray-800"
                  }`}
                >
                  <span
                    className={`absolute top-[2px] h-4 w-4 rounded-full bg-white transition-all ${
                      feed.enabled ? "left-[21px]" : "left-[2px]"
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
