import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuthenticatedSession } from "../lib/useSession";
import {
  getWeather,
  getNews,
  getNewsConfig,
  listFeeds,
  setFeedSubscription,
  searchWeb,
  getSearchPrefs,
  updateSearchPrefs,
  ApiError,
  type WeatherResponse,
  type NewsArticle,
  type NewsConfig,
  type Feed,
  type WebResult,
  type SearchPrefs,
  type SearchCategory,
  type SearchTimeRange,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { AppShell } from "../components/AppShell";
import { QuickLinksGrid } from "../components/QuickLinksGrid";
import { listQuickLinks, type Tile } from "../lib/quicklinks";

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
//
// Weather widget (spec section 8):
// - Browser Geolocation API supplies lat/lon on mount (one-time permission
//   prompt, no stored location on the server).
// - Core's /v1/widgets/weather proxies Open-Meteo and caches 15min in Valkey.
// - Inline in Hero: icon + temp + description, click opens the detail panel.
// - Detail panel: day-view (next 24h hourly) + 16-day forecast.
// - Graceful degradation: no weather if permission denied or fetch fails.
//
// News widget:
// - Compact preview on home shows up to prefs.home_article_count articles.
// - "All news →" opens a full slide panel with all articles + settings.
// - Settings (count + image toggle) are stored server-side per user so they
//   sync across devices.
// - News is fetched once on mount. useAuthenticatedSession re-creates the
//   session object on every 15s poll, which would trigger loadNews on every
//   poll if we used useEffect([session]) directly. We guard with a ref so
//   news only loads once on initial mount and on explicit user actions.
export default function Home() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const location = useLocation();
  const navigate = useNavigate();
  const [weather, setWeather] = useState<WeatherResponse | null>(null);
  const [weatherPanelOpen, setWeatherPanelOpen] = useState(false);
  const [feedsPanelOpen, setFeedsPanelOpen] = useState(false);
  const [newsAllOpen, setNewsAllOpen] = useState(false);

  // Web search state. searchQuery drives the URL (?q=...) and the results
  // panel. searxngAvailable starts as true (optimistic) and flips to false
  // on the first 503 - that permanently hides the web-results section for
  // the rest of the page lifetime without any explicit user action.
  const [searchQuery, setSearchQuery] = useState<string>(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("q") ?? "";
  });
  const [webResults, setWebResults] = useState<WebResult[] | null>(null);
  const [webLoading, setWebLoading] = useState(false);
  const [searxngAvailable, setSearxngAvailable] = useState(true);
  const [category, setCategory] = useState<SearchCategory>("general");
  const [timeRange, setTimeRange] = useState<SearchTimeRange>("");
  const [searchPrefs, setSearchPrefs] = useState<SearchPrefs>({ safesearch: 0, language: "all" });

  // Clear search results whenever the URL loses its ?q= parameter — e.g.
  // when the user clicks the ModuLab logo (navigate("/")) or uses the
  // browser back button to return to the bare home page.
  useEffect(() => {
    const q = new URLSearchParams(location.search).get("q") ?? "";
    if (!q) {
      setSearchQuery("");
      setWebResults(null);
      setWebLoading(false);
    }
  }, [location.search]);

  // Quick links state
  const [tiles, setTiles] = useState<Tile[]>([]);

  // News state
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [newsLoading, setNewsLoading] = useState(true);
  const [prefs, setPrefs] = useState<NewsConfig>({ home_count: 5, show_images: true });

  // Geolocation: ask once on mount, fetch weather on success.
  // Errors (denied, unavailable) are silently ignored - the widget
  // simply does not render, which is the correct degraded state.
  useEffect(() => {
    if (!navigator.geolocation) {
      return;
    }
    navigator.geolocation.getCurrentPosition(
      ({ coords }) => {
        getWeather(coords.latitude, coords.longitude)
          .then(setWeather)
          .catch(() => {});
      },
      () => {},
      { timeout: 8000 },
    );
  }, []);

  const loadNews = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    setNewsLoading(true);
    getNews(token)
      .then((arts) => setArticles(arts ?? []))
      .catch(() => setArticles([]))
      .finally(() => setNewsLoading(false));
  }, []);

  const loadPrefs = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    getNewsConfig(token)
      .then(setPrefs)
      .catch(() => {});
  }, []);

  const loadSearchPrefs = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    getSearchPrefs(token)
      .then(setSearchPrefs)
      .catch(() => {});
  }, []);

  const loadTiles = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    listQuickLinks(token)
      .then((t) => setTiles(t ?? []))
      .catch(() => {});
  }, []);

  // Guard: only load news+prefs once on initial session, not on every 15s poll.
  // useAuthenticatedSession creates a new session object on each /v1/auth/me
  // response, so session reference changes on every poll - without this ref
  // loadNews would fire every 15 seconds and flash "Loading…" endlessly.
  const initialLoadDone = useRef(false);
  useEffect(() => {
    if (session && !initialLoadDone.current) {
      initialLoadDone.current = true;
      loadNews();
      loadPrefs();
      loadSearchPrefs();
      loadTiles();
    }
  }, [session, loadNews, loadPrefs, loadSearchPrefs, loadTiles]);

  // handleSearch is called by Hero when the user submits the search box,
  // or by the category tab switcher when the user switches tabs.
  // It updates the URL (?q=...) without a page navigation and fires the
  // SearXNG proxy. A 503 response means SearXNG is not configured - flip
  // the flag so the results section stays hidden for the rest of this load.
  const handleSearch = useCallback(
    async (q: string, cat: SearchCategory = category, tr: SearchTimeRange = timeRange) => {
      const trimmed = q.trim();
      setSearchQuery(trimmed);

      // Update URL via React Router so location.search stays in sync and
      // the clear-on-navigate effect fires correctly. replace:true avoids
      // flooding the browser history with every keystroke search.
      navigate(trimmed ? `/?q=${encodeURIComponent(trimmed)}` : "/", { replace: true });

      if (!trimmed || !searxngAvailable) {
        setWebResults(null);
        return;
      }

      const token = getSessionToken();
      if (!token) return;

      setWebLoading(true);
      setWebResults(null);
      try {
        const results = await searchWeb(token, trimmed, cat, tr);
        setWebResults(results);
      } catch (err) {
        if (err instanceof ApiError && err.status === 503) {
          // SearXNG not configured - hide the section silently.
          setSearxngAvailable(false);
        }
        setWebResults([]);
      } finally {
        setWebLoading(false);
      }
    },
    [searxngAvailable, navigate, category, timeRange],
  );

  // Switch category tab and re-fire the current query with the new category.
  const handleCategoryChange = useCallback(
    (cat: SearchCategory) => {
      setCategory(cat);
      if (searchQuery) {
        handleSearch(searchQuery, cat, timeRange);
      }
    },
    [searchQuery, handleSearch, timeRange],
  );

  // Change time range and immediately re-fire the current query.
  const handleTimeRangeChange = useCallback(
    (tr: SearchTimeRange) => {
      setTimeRange(tr);
      if (searchQuery) {
        handleSearch(searchQuery, category, tr);
      }
    },
    [searchQuery, handleSearch, category],
  );

  // If the page was loaded with ?q=... (e.g. from a bookmark or browser
  // back/forward), fire the search immediately after the session resolves.
  const initialSearchDone = useRef(false);
  useEffect(() => {
    if (session && searchQuery && !initialSearchDone.current) {
      initialSearchDone.current = true;
      handleSearch(searchQuery);
    }
  }, [session, searchQuery, handleSearch]);

  // Renders nothing rather than a spinner during the brief getMe() round
  // trip - this page is reached almost exclusively via redirects (from
  // AuthComplete or useAuthenticatedSession's own guard), so there is
  // essentially never a "long" loading state worth designing for.
  if (loading || !session) {
    return null;
  }

  return (
    <>
      <AppShell session={session}>
        <Hero
          name={firstName(session)}
          weather={weather}
          onWeatherClick={() => setWeatherPanelOpen(true)}
          onSearch={handleSearch}
          initialQuery={searchQuery}
        />
        {/* Web/image search results: shown when a query is active and SearXNG
            is configured. Pushes the module/news sections downward inline. */}
        {searxngAvailable && (webLoading || webResults !== null) && (
          <WebResultsPanel
            results={webResults}
            loading={webLoading}
            category={category}
            onCategoryChange={handleCategoryChange}
            timeRange={timeRange}
            onTimeRangeChange={handleTimeRangeChange}
            searchPrefs={searchPrefs}
            onPrefsChange={async (patch) => {
              const token = getSessionToken();
              if (!token) return;
              try {
                const updated = await updateSearchPrefs(token, patch);
                setSearchPrefs(updated);
              } catch {
                // silently ignore — local state stays unchanged
              }
            }}
          />
        )}
        <div className="mx-auto max-w-3xl pb-8 px-4">
          <div className="mb-3 px-1">
            <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
              {t("home.quick_links")}
            </p>
          </div>
          <QuickLinksGrid initialTiles={tiles} token={getSessionToken() ?? ""} />
        </div>
        <NewsPreview
          articles={articles}
          loading={newsLoading}
          prefs={prefs}
          onOpenAll={() => setNewsAllOpen(true)}
          onOpenFeeds={() => setFeedsPanelOpen(true)}
        />
      </AppShell>

      {/* Weather detail panel */}
      {weather && (
        <WeatherPanel
          open={weatherPanelOpen}
          weather={weather}
          onClose={() => setWeatherPanelOpen(false)}
        />
      )}

      {/* Full news panel — all articles + settings */}
      <NewsAllPanel
        open={newsAllOpen}
        articles={articles}
        prefs={prefs}
        onOpenFeeds={() => {
          setNewsAllOpen(false);
          setFeedsPanelOpen(true);
        }}
        onClose={() => setNewsAllOpen(false)}
      />

      {/* Feed subscription panel */}
      <FeedsPanel
        open={feedsPanelOpen}
        onClose={() => {
          setFeedsPanelOpen(false);
          loadNews();
        }}
      />
    </>
  );
}

// --- Hero (clock, greeting, weather inline, search) ----------------------

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 30_000);
    return () => window.clearInterval(id);
  }, []);
  return now;
}


function Hero({
  name,
  weather,
  onWeatherClick,
  onSearch,
  initialQuery,
}: {
  name: string;
  weather: WeatherResponse | null;
  onWeatherClick: () => void;
  onSearch: (q: string) => void;
  initialQuery: string;
}) {
  const { t, i18n: i18nInstance } = useTranslation();
  const now = useClock();
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const hour = now.getHours();
  const greeting = hour < 12 ? t("home.greeting_morning") : hour < 18 ? t("home.greeting_afternoon") : t("home.greeting_evening");
  const weekday = new Intl.DateTimeFormat(i18nInstance.language, { weekday: "long" }).format(now);
  const month = new Intl.DateTimeFormat(i18nInstance.language, { month: "long" }).format(now);

  // Controlled input so we can clear it programmatically (e.g. when the user
  // navigates back to the blank home page state).
  const [value, setValue] = useState(initialQuery);

  // Sync local value when the parent clears initialQuery (e.g. logo click
  // navigates to "/" which triggers the location.search effect in Home and
  // resets searchQuery to "").
  useEffect(() => {
    setValue(initialQuery);
  }, [initialQuery]);

  function handleSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Enter") {
      return;
    }
    onSearch(e.currentTarget.value);
  }

  return (
    <div className="flex flex-col items-center py-9 sm:py-14">
      <p className="m-0 text-[clamp(38px,12vw,64px)] font-semibold leading-none tracking-tight">
        {hours}
        <span className="text-teal-600 dark:text-teal-400">:</span>
        {minutes}
      </p>
      <p className="mt-2 text-center text-[13.5px] text-gray-500 dark:text-gray-400">
        {weekday}, {now.getDate()} {month} · {greeting}, {name}
      </p>

      {/* Inline weather — only rendered once geolocation + fetch succeed */}
      {weather && (
        <button
          type="button"
          onClick={onWeatherClick}
          className="mt-2 mb-4 flex items-center gap-1.5 rounded-full px-3 py-1 text-[13px] text-gray-500 transition-colors hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-900"
        >
          <i
            className={`ti ${wmoIcon(weather.current.weather_code)} text-teal-600 dark:text-teal-400`}
            style={{ fontSize: 15 }}
            aria-hidden="true"
          />
          <span className="font-medium text-gray-800 dark:text-gray-200">
            {Math.round(weather.current.temperature)}°C
          </span>
          <span>·</span>
          <span>{t(wmoKey(weather.current.weather_code))}</span>
          <i className="ti ti-chevron-right text-[11px] text-gray-400" aria-hidden="true" />
        </button>
      )}

      {/* Spacer when weather widget is absent to maintain consistent search position */}
      {!weather && <div className="mb-6" />}

      <div className="flex h-11 w-full max-w-[440px] items-center gap-2.5 rounded-full border border-teal-600/35 px-[18px]">
        <i className="ti ti-search text-[16px] text-teal-600 dark:text-teal-400" aria-hidden="true" />
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleSearchKeyDown}
          placeholder={t("home.search_placeholder")}
          className="w-full flex-1 bg-transparent text-base outline-none placeholder:text-gray-400 md:text-sm"
        />
        {value && (
          <button
            type="button"
            aria-label={t("home.search_clear")}
            onClick={() => {
              setValue("");
              onSearch("");
            }}
            className="flex-none text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
          >
            <i className="ti ti-x text-[14px]" aria-hidden="true" />
          </button>
        )}
      </div>
    </div>
  );
}

// --- Web / image search results panel ------------------------------------

// Available languages for the filter dropdown.
const SEARCH_LANGUAGES = [
  { value: "all", label: "All languages" },
  { value: "de", label: "Deutsch" },
  { value: "en", label: "English" },
  { value: "fr", label: "Français" },
  { value: "es", label: "Español" },
  { value: "it", label: "Italiano" },
  { value: "nl", label: "Nederlands" },
  { value: "pl", label: "Polski" },
  { value: "pt", label: "Português" },
  { value: "ru", label: "Русский" },
  { value: "zh", label: "中文" },
];

// Inline results panel that appears directly below the Hero when a search
// is active. Includes a Web/Images tab switcher and a filter dropdown for
// safesearch and language.
const TIME_RANGE_OPTIONS: { value: SearchTimeRange; key: string }[] = [
  { value: "", key: "home.search.time_any" },
  { value: "day", key: "home.search.time_day" },
  { value: "week", key: "home.search.time_week" },
  { value: "month", key: "home.search.time_month" },
  { value: "year", key: "home.search.time_year" },
];

function WebResultsPanel({
  results,
  loading,
  category,
  onCategoryChange,
  timeRange,
  onTimeRangeChange,
  searchPrefs,
  onPrefsChange,
}: {
  results: WebResult[] | null;
  loading: boolean;
  category: SearchCategory;
  onCategoryChange: (cat: SearchCategory) => void;
  timeRange: SearchTimeRange;
  onTimeRangeChange: (tr: SearchTimeRange) => void;
  searchPrefs: SearchPrefs;
  onPrefsChange: (patch: Partial<SearchPrefs>) => void;
}) {
  const { t } = useTranslation();
  const [filterOpen, setFilterOpen] = useState(false);

  return (
    <div className="mx-auto mb-8 w-full max-w-[680px]">
      {/* Tab bar + filter button */}
      <div className="mb-3 flex items-center justify-between px-1">
        <div className="flex items-center gap-1">
          {(["general", "images"] as SearchCategory[]).map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => onCategoryChange(cat)}
              className={`rounded-full px-3 py-1 text-[12px] font-medium transition-colors ${
                category === cat
                  ? "bg-teal-600 text-white"
                  : "text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
              }`}
            >
              {cat === "general" ? t("home.search.tab_web") : t("home.search.tab_images")}
            </button>
          ))}
        </div>

        {/* Filter toggle */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setFilterOpen((v) => !v)}
            className={`flex items-center gap-1 rounded-full px-2.5 py-1 text-[12px] transition-colors ${
              filterOpen || timeRange
                ? "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200"
                : "text-gray-400 hover:bg-gray-100 dark:text-gray-500 dark:hover:bg-gray-800"
            }`}
          >
            <i className="ti ti-adjustments-horizontal text-[13px]" aria-hidden="true" />
            {timeRange
              ? t(TIME_RANGE_OPTIONS.find((o) => o.value === timeRange)?.key ?? "home.search.filter")
              : t("home.search.filter")}
          </button>

          {filterOpen && (
            <div className="absolute right-0 z-10 mt-1 w-56 rounded-xl border border-gray-200 bg-white p-3 shadow-lg dark:border-gray-700 dark:bg-gray-900">
              {/* Time range */}
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
                {t("home.search.time_label")}
              </p>
              <div className="mb-3 flex flex-col gap-0.5">
                {TIME_RANGE_OPTIONS.map(({ value, key }) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => onTimeRangeChange(value)}
                    className={`w-full rounded-lg px-2.5 py-1.5 text-left text-[12px] transition-colors ${
                      timeRange === value
                        ? "bg-teal-600 text-white"
                        : "text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
                    }`}
                  >
                    {t(key)}
                  </button>
                ))}
              </div>

              {/* Safesearch */}
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
                {t("home.search.safesearch")}
              </p>
              <div className="mb-3 flex gap-1">
                {([0, 1, 2] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => onPrefsChange({ safesearch: v })}
                    className={`flex-1 rounded-lg py-1 text-[11px] font-medium transition-colors ${
                      searchPrefs.safesearch === v
                        ? "bg-teal-600 text-white"
                        : "border border-gray-200 text-gray-600 hover:border-teal-400 dark:border-gray-700 dark:text-gray-300"
                    }`}
                  >
                    {v === 0 ? t("home.search.safe_off") : v === 1 ? t("home.search.safe_moderate") : t("home.search.safe_strict")}
                  </button>
                ))}
              </div>

              {/* Language */}
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
                {t("home.search.language")}
              </p>
              <select
                value={searchPrefs.language}
                onChange={(e) => onPrefsChange({ language: e.target.value })}
                className="w-full rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-[12px] text-gray-700 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
              >
                {SEARCH_LANGUAGES.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.value === "all" ? t("home.search.language_all") : l.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Results */}
      {loading ? (
        category === "images" ? (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse aspect-video rounded-xl bg-gray-100 dark:bg-gray-800"
              />
            ))}
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse rounded-xl border border-gray-100 p-4 dark:border-gray-800"
              >
                <div className="mb-2 h-3.5 w-3/4 rounded bg-gray-100 dark:bg-gray-800" />
                <div className="mb-1 h-3 w-1/3 rounded bg-gray-100 dark:bg-gray-800" />
                <div className="h-3 w-full rounded bg-gray-100 dark:bg-gray-800" />
              </div>
            ))}
          </div>
        )
      ) : results && results.length > 0 ? (
        category === "images" ? (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {results.map((r, i) => (
              <ImageResultCard key={`${r.url}-${i}`} result={r} />
            ))}
          </div>
        ) : (
          <div className="flex flex-col divide-y divide-gray-100 rounded-2xl border border-gray-100 dark:divide-gray-800 dark:border-gray-800">
            {results.map((r, i) => (
              <WebResultCard key={`${r.url}-${i}`} result={r} />
            ))}
          </div>
        )
      ) : (
        <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-8 text-center dark:border-gray-700">
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("home.search.no_results")}</p>
        </div>
      )}
    </div>
  );
}

function WebResultCard({ result }: { result: WebResult }) {
  let host = result.url;
  try {
    host = new URL(result.url).hostname.replace(/^www\./, "");
  } catch {
    // leave as-is if URL is malformed
  }

  return (
    <a
      href={result.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex flex-col gap-0.5 px-5 py-3.5 first:rounded-t-2xl last:rounded-b-2xl hover:bg-gray-50 dark:hover:bg-gray-900"
    >
      <p className="text-[11px] text-gray-400 dark:text-gray-500">{host}</p>
      <p className="text-sm font-medium leading-snug text-blue-700 group-hover:underline dark:text-blue-400">
        {result.title}
      </p>
      {result.snippet && (
        <p className="line-clamp-2 text-[13px] text-gray-600 dark:text-gray-400">
          {result.snippet}
        </p>
      )}
    </a>
  );
}

function ImageResultCard({ result }: { result: WebResult }) {
  const src = result.thumbnail || result.img_src;
  if (!src) return null;

  return (
    <a
      href={result.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group relative block overflow-hidden rounded-xl bg-gray-100 dark:bg-gray-800"
      title={result.title}
    >
      <img
        src={src}
        alt={result.title}
        loading="lazy"
        className="aspect-video w-full object-cover transition-opacity group-hover:opacity-90"
      />
      {/* Title overlay on hover */}
      <div className="absolute inset-x-0 bottom-0 translate-y-full bg-black/70 px-2 py-1.5 transition-transform group-hover:translate-y-0">
        <p className="line-clamp-2 text-[11px] leading-tight text-white">{result.title}</p>
      </div>
    </a>
  );
}

// --- Weather detail panel ------------------------------------------------

function WeatherPanel({
  open,
  weather,
  onClose,
}: {
  open: boolean;
  weather: WeatherResponse;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  // Close on Escape key.
  useEffect(() => {
    if (!open) return;
    function onKey(e: globalThis.KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <>
      {/* Backdrop — sits between AppShell (z-20) and the panel (z-30) */}
      <div
        className={`fixed inset-x-0 top-[60px] bottom-[44px] z-[25] bg-black/35 transition-opacity duration-200 ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />

      {/* Slide panel — same dimensions as AppShell's own panels */}
      <div
        className={`fixed top-[60px] bottom-[44px] right-0 z-30 flex w-full flex-col border-l border-gray-200 bg-white shadow-xl transition-transform duration-200 sm:w-[360px] dark:border-gray-800 dark:bg-gray-950 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex flex-none items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-800">
          <h2 className="text-base font-semibold">{t("home.weather.panel_title")}</h2>
          <button
            type="button"
            aria-label={t("shell.close")}
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-x" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5">
          <WeatherPanelContent weather={weather} />
        </div>
      </div>
    </>
  );
}

function WeatherPanelContent({ weather }: { weather: WeatherResponse }) {
  const { t, i18n: i18nInstance } = useTranslation();
  const { current, hourly, daily } = weather;

  return (
    <>
      {/* Current conditions */}
      <div className="mb-5 flex items-center gap-4">
        <i
          className={`ti ${wmoIcon(current.weather_code)} text-teal-600 dark:text-teal-400`}
          style={{ fontSize: 40 }}
          aria-hidden="true"
        />
        <div>
          <p className="text-3xl font-semibold leading-none">
            {Math.round(current.temperature)}°C
          </p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t(wmoKey(current.weather_code))}
          </p>
          <div className="mt-1.5 flex gap-3 text-xs text-gray-500 dark:text-gray-400">
            <span className="flex items-center gap-1">
              <i className="ti ti-thermometer" aria-hidden="true" />
              {t("home.weather.feels", { temp: Math.round(current.apparent_temperature) })}
            </span>
            <span className="flex items-center gap-1">
              <i className="ti ti-droplet" aria-hidden="true" />
              {current.humidity}%
            </span>
            <span className="flex items-center gap-1">
              <i className="ti ti-wind" aria-hidden="true" />
              {Math.round(current.wind_speed)} km/h
            </span>
          </div>
        </div>
      </div>

      {/* Hourly — next 24 hours */}
      <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {t("home.weather.next_24h")}
      </p>
      <div
        className="mb-5 flex overflow-x-auto rounded-xl border border-gray-100 dark:border-gray-800"
        style={{ scrollbarWidth: "none" }}
      >
        {hourly.map((h, i) => {
          const timeLabel = i === 0 ? t("home.weather.now") : formatHourLabel(h.time);
          return (
            <div
              key={h.time}
              className={`flex flex-none flex-col items-center gap-1 border-r border-gray-100 px-3 py-2.5 last:border-r-0 dark:border-gray-800 ${
                i === 0 ? "bg-teal-50 dark:bg-teal-950/30" : ""
              }`}
            >
              <span
                className={`text-[11px] ${
                  i === 0
                    ? "font-medium text-teal-700 dark:text-teal-400"
                    : "text-gray-400 dark:text-gray-500"
                }`}
              >
                {timeLabel}
              </span>
              <i
                className={`ti ${wmoIcon(h.weather_code)} text-teal-600 dark:text-teal-400`}
                style={{ fontSize: 14 }}
                aria-hidden="true"
              />
              <span className="text-[12px] font-medium">{Math.round(h.temperature)}°</span>
              <span className="text-[10px] text-gray-400 dark:text-gray-500">
                {h.precip_probability}%
              </span>
            </div>
          );
        })}
      </div>

      {/* 16-day daily forecast */}
      <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {t("home.weather.forecast_16d")}
      </p>
      <div className="rounded-xl border border-gray-100 dark:border-gray-800">
        {daily.map((d, i) => {
          const isToday = i === 0;
          return (
            <div
              key={d.time}
              className={`flex items-center gap-3 border-b border-gray-100 px-3 py-2 last:border-b-0 dark:border-gray-800 ${
                isToday ? "bg-teal-50 dark:bg-teal-950/30" : ""
              }`}
            >
              <span
                className={`w-7 shrink-0 text-[12px] ${
                  isToday
                    ? "font-medium text-teal-700 dark:text-teal-400"
                    : "text-gray-500 dark:text-gray-400"
                }`}
              >
                {isToday ? t("home.weather.today") : formatDayLabel(d.time, i18nInstance.language)}
              </span>
              <i
                className={`ti ${wmoIcon(d.weather_code)} shrink-0 text-teal-600 dark:text-teal-400`}
                style={{ fontSize: 14 }}
                aria-hidden="true"
              />
              {/* Precipitation probability bar */}
              <div className="flex-1">
                <div className="h-1 rounded-full bg-gray-100 dark:bg-gray-800">
                  <div
                    className="h-1 rounded-full bg-teal-400 dark:bg-teal-600"
                    style={{ width: `${d.precip_prob_max}%` }}
                  />
                </div>
              </div>
              <div className="flex shrink-0 gap-2 text-[12px]">
                <span className="font-medium">{Math.round(d.temp_max)}°</span>
                <span className="text-gray-400 dark:text-gray-500">{Math.round(d.temp_min)}°</span>
              </div>
            </div>
          );
        })}
      </div>

      <p className="mt-3 text-center text-[11px] text-gray-400 dark:text-gray-600">
        {t("home.weather.source")}
      </p>
    </>
  );
}

// --- WMO weather code helpers --------------------------------------------

// Maps WMO weather interpretation codes to Tabler outline icon names.
// https://open-meteo.com/en/docs#weathervariables
function wmoIcon(code: number): string {
  if (code === 0 || code === 1) return "ti-sun";
  if (code === 2) return "ti-cloud-sun";
  if (code === 3) return "ti-cloud";
  if (code === 45 || code === 48) return "ti-cloud-fog";
  if (code >= 51 && code <= 57) return "ti-cloud-drizzle";
  if (code >= 61 && code <= 67) return "ti-cloud-rain";
  if (code >= 71 && code <= 77) return "ti-snowflake";
  if (code >= 80 && code <= 82) return "ti-cloud-rain";
  if (code === 85 || code === 86) return "ti-snowflake";
  if (code >= 95) return "ti-cloud-storm";
  return "ti-cloud";
}

// Maps WMO codes to i18n translation keys under home.weather.desc.*
function wmoKey(code: number): string {
  if (code === 0) return "home.weather.desc.clear";
  if (code === 1) return "home.weather.desc.mainly_clear";
  if (code === 2) return "home.weather.desc.partly_cloudy";
  if (code === 3) return "home.weather.desc.overcast";
  if (code === 45 || code === 48) return "home.weather.desc.fog";
  if (code === 51 || code === 53) return "home.weather.desc.drizzle";
  if (code === 55) return "home.weather.desc.heavy_drizzle";
  if (code === 56 || code === 57) return "home.weather.desc.freezing_drizzle";
  if (code === 61 || code === 63) return "home.weather.desc.rain";
  if (code === 65) return "home.weather.desc.heavy_rain";
  if (code === 66 || code === 67) return "home.weather.desc.freezing_rain";
  if (code === 71 || code === 73) return "home.weather.desc.snow";
  if (code === 75) return "home.weather.desc.heavy_snow";
  if (code === 77) return "home.weather.desc.snow_grains";
  if (code === 80 || code === 81) return "home.weather.desc.rain_showers";
  if (code === 82) return "home.weather.desc.heavy_showers";
  if (code === 85 || code === 86) return "home.weather.desc.snow_showers";
  if (code === 95) return "home.weather.desc.thunderstorm";
  if (code === 96 || code === 99) return "home.weather.desc.thunderstorm_hail";
  return "home.weather.desc.unknown";
}

// --- Time/date formatting ------------------------------------------------

// Formats an ISO hourly time string ("2026-06-23T14:00") to a short label
// ("14h"). Used in the day-view hourly row.
function formatHourLabel(isoTime: string): string {
  const hour = isoTime.slice(11, 13);
  return `${parseInt(hour, 10)}h`;
}

// Formats an ISO date string ("2026-06-23") to a locale-aware short weekday.
function formatDayLabel(isoDate: string, locale: string): string {
  const d = new Date(isoDate + "T12:00:00"); // noon avoids DST edge cases
  return new Intl.DateTimeFormat(locale, { weekday: "short" }).format(d);
}

// --- News preview (compact, home page) -----------------------------------

// Shows a limited number of articles on the home page based on user prefs.
// "All news →" button opens the full NewsAllPanel.
function NewsPreview({
  articles,
  loading,
  prefs,
  onOpenAll,
  onOpenFeeds,
}: {
  articles: NewsArticle[];
  loading: boolean;
  prefs: NewsConfig;
  onOpenAll: () => void;
  onOpenFeeds: () => void;
}) {
  const { t } = useTranslation();
  const preview = articles.slice(0, prefs.home_count);

  return (
    <div className="mx-auto max-w-3xl pb-14">
      <div className="mb-3 px-1">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
          {t("home.news.section_title")}
        </p>
      </div>

      {loading ? (
        <div className="rounded-2xl border border-gray-100 px-6 py-8 text-center dark:border-gray-800">
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("home.news.loading")}</p>
        </div>
      ) : articles.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-200">{t("home.news.empty_title")}</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t("home.news.empty_body")}
          </p>
          <button
            type="button"
            onClick={onOpenFeeds}
            className="mt-3 rounded-lg border border-gray-300 px-4 py-1.5 text-sm hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900"
          >
            {t("home.news.choose_feeds")}
          </button>
        </div>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            {preview.map((a, i) => (
              <ArticleCard key={`${a.url}-${i}`} article={a} showImage={prefs.show_images} />
            ))}
          </div>
          {articles.length > prefs.home_count && (
            <button
              type="button"
              onClick={onOpenAll}
              className="mt-3 w-full rounded-xl border border-gray-100 py-2.5 text-[13px] text-gray-500 hover:bg-gray-50 dark:border-gray-800 dark:text-gray-400 dark:hover:bg-gray-900"
            >
              {t("home.news.show_all", { count: articles.length })}
            </button>
          )}
        </>
      )}
    </div>
  );
}

// --- Full news panel (all articles + settings) ---------------------------

function NewsAllPanel({
  open,
  articles,
  prefs,
  onOpenFeeds,
  onClose,
}: {
  open: boolean;
  articles: NewsArticle[];
  prefs: NewsConfig;
  onOpenFeeds: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  useEffect(() => {
    if (!open) return;
    function onKey(e: globalThis.KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <>
      <div
        className={`fixed inset-x-0 top-[60px] bottom-[44px] z-[25] bg-black/35 transition-opacity duration-200 ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />
      <div
        className={`fixed top-[60px] bottom-[44px] right-0 z-30 flex w-full flex-col border-l border-gray-200 bg-white shadow-xl transition-transform duration-200 sm:w-[420px] dark:border-gray-800 dark:bg-gray-950 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        {/* Header */}
        <div className="flex flex-none items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-800">
          <h2 className="text-base font-semibold">{t("home.news.section_title")}</h2>
          <button
            type="button"
            aria-label={t("shell.close")}
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-x" aria-hidden="true" />
          </button>
        </div>

        {/* Article list */}
        <div className="flex-1 overflow-y-auto p-3">
          {articles.length === 0 ? (
            <div className="px-2 py-10 text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">{t("home.news.empty_panel")}</p>
              <button
                type="button"
                onClick={onOpenFeeds}
                className="mt-2 text-[13px] text-teal-600 hover:underline dark:text-teal-400"
              >
                {t("home.news.choose_feeds_link")}
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {articles.map((a, i) => (
                <ArticleCard
                  key={`${a.url}-${i}`}
                  article={a}
                  showImage={prefs.show_images}
                  compact
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// --- Article card --------------------------------------------------------

// Two modes:
//   compact=false (default): grid card with optional image, used on home preview.
//   compact=true: horizontal list row used in the full news panel.
function ArticleCard({
  article,
  showImage,
  compact = false,
}: {
  article: NewsArticle;
  showImage: boolean;
  compact?: boolean;
}) {
  const pub = article.published_at ? new Date(article.published_at) : null;
  const age = pub ? relativeNewsTime(pub) : null;

  if (compact) {
    return (
      <a
        href={article.url}
        target="_blank"
        rel="noopener noreferrer"
        className="group flex items-start gap-3 rounded-xl px-2.5 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        {showImage && article.image_url && (
          <img
            src={article.image_url}
            alt=""
            className="mt-0.5 h-14 w-14 shrink-0 rounded-lg object-cover"
            loading="lazy"
          />
        )}
        <div className="min-w-0 flex-1">
          <p className="line-clamp-2 text-[13px] font-medium leading-snug group-hover:text-teal-600 dark:group-hover:text-teal-400">
            {article.title}
          </p>
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-gray-400 dark:text-gray-500">
            <span className="truncate font-medium text-gray-500 dark:text-gray-400">
              {article.source}
            </span>
            {age && (
              <>
                <span>·</span>
                <span>{age}</span>
              </>
            )}
          </div>
        </div>
      </a>
    );
  }

  return (
    <a
      href={article.url}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex flex-col overflow-hidden rounded-xl border border-gray-100 bg-white transition-shadow hover:shadow-md dark:border-gray-800 dark:bg-gray-900"
    >
      {showImage && article.image_url && (
        <img
          src={article.image_url}
          alt=""
          className="h-36 w-full object-cover"
          loading="lazy"
        />
      )}
      <div className="flex flex-1 flex-col gap-1 p-3">
        <p className="line-clamp-3 text-sm font-medium leading-snug group-hover:text-teal-600 dark:group-hover:text-teal-400">
          {article.title}
        </p>
        <div className="mt-auto flex items-center gap-1.5 pt-1 text-[11px] text-gray-400 dark:text-gray-500">
          <span className="truncate font-medium text-gray-500 dark:text-gray-400">
            {article.source}
          </span>
          {age && (
            <>
              <span>·</span>
              <span>{age}</span>
            </>
          )}
        </div>
      </div>
    </a>
  );
}

function relativeNewsTime(date: Date): string {
  const diff = Math.max(0, Date.now() - date.getTime());
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// --- Feeds selection panel -----------------------------------------------

function FeedsPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [fetching, setFetching] = useState(false);
  const [toggling, setToggling] = useState<number | null>(null);

  // Load feed list whenever the panel opens.
  useEffect(() => {
    if (!open) return;
    const token = getSessionToken();
    if (!token) return;
    setFetching(true);
    listFeeds(token)
      .then((f) => setFeeds(f ?? []))
      .catch(() => {})
      .finally(() => setFetching(false));
  }, [open]);

  async function handleToggle(feed: Feed) {
    const token = getSessionToken();
    if (!token || toggling !== null) return;
    const next = !feed.enabled;
    setToggling(feed.id);
    // Optimistic update
    setFeeds((prev) => prev.map((f) => (f.id === feed.id ? { ...f, enabled: next } : f)));
    try {
      await setFeedSubscription(token, feed.id, next);
    } catch {
      // Roll back on error
      setFeeds((prev) => prev.map((f) => (f.id === feed.id ? { ...f, enabled: feed.enabled } : f)));
    } finally {
      setToggling(null);
    }
  }

  return (
    <>
      {open && (
        <div
          className="fixed inset-x-0 top-[60px] bottom-[44px] z-[25] bg-black/35"
          onClick={onClose}
        />
      )}
      <div
        className={`fixed top-[60px] bottom-[44px] right-0 z-30 flex w-full flex-col border-l border-gray-200 bg-white shadow-xl transition-transform duration-200 sm:w-[380px] dark:border-gray-800 dark:bg-gray-950 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex flex-none items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-800">
          <h2 className="text-base font-semibold">{t("home.feeds.panel_title")}</h2>
          <button
            type="button"
            aria-label={t("shell.close")}
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-x" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-2.5">
          {fetching ? (
            <p className="px-2.5 py-4 text-sm text-gray-500 dark:text-gray-400">{t("home.feeds.loading")}</p>
          ) : feeds.length === 0 ? (
            <p className="px-2.5 py-4 text-sm text-gray-500 dark:text-gray-400">
              {t("home.feeds.no_feeds")}
            </p>
          ) : (
            feeds.map((feed) => (
              <div
                key={feed.id}
                className="flex items-center gap-3 rounded-lg px-2.5 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-900"
              >
                <i className="ti ti-rss shrink-0 text-[15px] text-teal-600 dark:text-teal-400" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{feed.label}</p>
                  <p className="truncate text-xs text-gray-500 dark:text-gray-400">{feed.url}</p>
                </div>
                {/* Toggle */}
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
            ))
          )}
        </div>
      </div>
    </>
  );
}

// --- Session helpers -----------------------------------------------------

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
