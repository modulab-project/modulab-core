import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  adminGetLimitsSettings,
  adminPatchLimitsSettings,
  adminCheckCoreUpdateNow,
  type LimitsSettings,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { isSuperAdminRole } from "../lib/roles";
import { AppShell } from "../components/AppShell";

// /admin/system/limits — consolidates every cross-cutting operational limit
// that used to be a hardcoded Go constant (request body size, module/ZIP/
// OPML upload caps, rate limits, Deno worker pool size, various HTTP
// timeouts). See backend/internal/adminapi/limits.go's doc comment for the
// incident that prompted this (module photo uploads silently capped at
// ~1 MB by a global middleware limit nested outside the module's own,
// larger limit) — that history is why every field still lives behind one
// GET/PATCH endpoint and one save button, even though the 16 fields are
// now split into five tabs below purely as a display grouping. A field
// moving tabs is a one-line change to its `tab`; it never risks being
// "lost" the way splitting into separate routes/endpoints would.
//
// The tabs used to be "uploads" / "ai_search" / "modules" / "system", but
// "ai_search" bundled two unrelated concerns (AI chat limits/timeouts vs.
// web-search timeouts) onto one tab purely because both happened to be
// small. Split into "ai" and "search"; news_fetch_timeout_seconds (RSS/Atom
// feed fetching — neither AI nor search) moved to "system", where the
// other single-purpose cross-cutting timeouts already live.
//
// Each field's `kind` selects which input component renders it (see
// renderField below) and, for handleSave's validation, whether 0 is a
// valid "unlimited" value (kind "byte", or `allowZero: true`) or not
// (every other field):
//   - "byte": canonical value is bytes; ByteField adds a Bytes/KB/MB unit
//     selector purely as a display/edit convenience — the unit choice is
//     not persisted anywhere, just re-derived from the byte value on load.
//   - "count": a plain integer (rate limit, pool size) — NumberField, no unit.
//   - "ms": canonical value is milliseconds (matches a browser API exactly,
//     e.g. geo_timeout_ms → navigator.geolocation's timeout option) —
//     SecondsField displays/edits in seconds.
//   - "seconds": canonical value is seconds, small range (single digits to
//     ~30s) — NumberField with a "seconds" suffix, no conversion needed.
//   - "minutes": canonical value is seconds, but in the minutes-to-hour
//     range (sync interval, download timeout) where a raw seconds count is
//     harder to read at a glance — MinutesField displays/edits in minutes.
//
// `allowZero` is independent of `kind`: chat_rpm_limit is a plain "count"
// like auth_rate_limit_max/global_rate_limit_max, but — like the byte caps
// — 0 means "unlimited" rather than being a rejected config mistake, since
// it moved here from max_body_bytes-style "0 = unlimited" semantics on its
// old single-field admin endpoint (see AdminLimitsHandler's doc comment).
type FieldKind = "byte" | "count" | "ms" | "seconds" | "minutes";
// "updates" (core_update_check_weekdays/_time + the manual "check now"
// button) is not in FIELDS below: unlike every other setting here, it isn't
// a plain integer, so it gets its own bespoke weekday-checkbox/time-input
// UI and its own local state (weekdayInput/timeInput) instead of going
// through FIELDS/renderField's generic number-parsing loop. It is still
// part of the same LimitsSettings object and the same PATCH request -
// see handleSave.
type Tab = "uploads" | "ai" | "search" | "modules" | "system" | "updates";
// NumericFieldKey excludes core_update_check_weekdays/_time - both strings,
// handled by their own bespoke UI/state above, never through this array's
// generic integer parse/render loop. Narrowing FIELDS to only the numeric
// keys (rather than the full keyof LimitsSettings) is what lets
// `parsed[f.key] = n` in handleSave type-check now that LimitsSettings has
// non-numeric fields too.
type NumericFieldKey = keyof Omit<LimitsSettings, "core_update_check_weekdays" | "core_update_check_time">;
const FIELDS: Array<{ key: NumericFieldKey; kind: FieldKind; tab: Tab; allowZero?: boolean }> = [
  { key: "max_body_bytes", kind: "byte", tab: "uploads" },
  { key: "max_opml_upload_bytes", kind: "byte", tab: "uploads" },
  { key: "chat_rpm_limit", kind: "count", tab: "ai", allowZero: true },
  { key: "ai_chat_ip_rate_limit_max", kind: "count", tab: "ai" },
  { key: "ai_provider_timeout_seconds", kind: "seconds", tab: "ai" },
  { key: "search_timeout_seconds", kind: "seconds", tab: "search" },
  { key: "search_fallback_timeout_seconds", kind: "seconds", tab: "search" },
  { key: "max_upload_body_bytes", kind: "byte", tab: "modules" },
  { key: "max_module_zip_bytes", kind: "byte", tab: "modules" },
  { key: "deno_conn_pool_size", kind: "count", tab: "modules" },
  { key: "modules_install_download_timeout_seconds", kind: "minutes", tab: "modules" },
  { key: "store_sync_interval_seconds", kind: "minutes", tab: "modules" },
  { key: "store_github_api_timeout_seconds", kind: "seconds", tab: "modules" },
  { key: "auth_rate_limit_max", kind: "count", tab: "system" },
  { key: "global_rate_limit_max", kind: "count", tab: "system" },
  { key: "geo_timeout_ms", kind: "ms", tab: "system" },
  { key: "news_fetch_timeout_seconds", kind: "seconds", tab: "system" },
];

const TABS: Array<{ id: Tab; icon: string }> = [
  { id: "uploads", icon: "ti-upload" },
  { id: "ai", icon: "ti-message-circle" },
  { id: "search", icon: "ti-search" },
  { id: "modules", icon: "ti-puzzle" },
  { id: "system", icon: "ti-server-2" },
  { id: "updates", icon: "ti-arrow-big-up-lines" },
];

// Weekday order shown in the checkbox row - Monday-first (matches this
// app's other weekday-picker conventions), each mapped to its
// time.Weekday/Date.getDay() integer (0=Sunday..6=Saturday) since that is
// the wire format core_update_check_weekdays actually stores.
const WEEKDAYS: Array<{ value: number; labelKey: string }> = [
  { value: 1, labelKey: "mon" },
  { value: 2, labelKey: "tue" },
  { value: 3, labelKey: "wed" },
  { value: 4, labelKey: "thu" },
  { value: 5, labelKey: "fri" },
  { value: 6, labelKey: "sat" },
  { value: 0, labelKey: "sun" },
];

type ByteUnit = "B" | "KB" | "MB";
const UNIT_FACTORS: Record<ByteUnit, number> = { B: 1, KB: 1024, MB: 1024 * 1024 };

// Picks the largest unit that divides `bytes` evenly, so e.g. 1048576
// shows as "1 MB" instead of "1048576 Bytes" on first load.
function detectUnit(bytes: number): ByteUnit {
  if (bytes !== 0 && bytes % UNIT_FACTORS.MB === 0) return "MB";
  if (bytes !== 0 && bytes % UNIT_FACTORS.KB === 0) return "KB";
  return "B";
}

export default function AdminSystemLimitsPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [settings, setSettings] = useState<LimitsSettings | null>(null);
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [units, setUnits] = useState<Record<string, ByteUnit>>({});
  const [activeTab, setActiveTab] = useState<Tab>("uploads");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  // core_update_check_weekdays/_time — kept separate from inputs/FIELDS
  // above (see Tab's doc comment): weekdayInput is the set of selected
  // weekday integers, timeInput the raw "HH:MM" string.
  const [weekdayInput, setWeekdayInput] = useState<Set<number>>(new Set());
  const [timeInput, setTimeInput] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    adminGetLimitsSettings()
      .then((s) => {
        setSettings(s);
        setInputs(Object.fromEntries(FIELDS.map((f) => [f.key, String(s[f.key])])));
        setUnits(Object.fromEntries(
          FIELDS.filter((f) => f.kind === "byte").map((f) => [f.key, detectUnit(Number(s[f.key]))]),
        ));
        setWeekdayInput(new Set(
          s.core_update_check_weekdays.split(",").map((v) => parseInt(v, 10)).filter((n) => !isNaN(n)),
        ));
        setTimeInput(s.core_update_check_time);
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system_limits.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  const dirty = settings !== null && (
    FIELDS.some((f) => inputs[f.key] !== String(settings[f.key])) ||
    Array.from(weekdayInput).sort().join(",") !== settings.core_update_check_weekdays.split(",").map((v) => parseInt(v, 10)).sort().join(",") ||
    timeInput !== settings.core_update_check_time
  );

  function toggleWeekday(value: number) {
    setWeekdayInput((prev) => {
      const next = new Set(prev);
      if (next.has(value)) {
        // At least one weekday must stay selected - see
        // coreupdate.ParseWeekdays, which rejects an empty set outright.
        if (next.size === 1) return next;
        next.delete(value);
      } else {
        next.add(value);
      }
      return next;
    });
  }

  async function handleCheckNow() {
    if (checking) return;
    setChecking(true);
    setCheckResult(null);
    try {
      const result = await adminCheckCoreUpdateNow();
      setCheckResult({
        ok: true,
        text: result.core_update_available && result.latest_core_version
          ? t("admin.system_limits.check_now_update_found", { version: result.latest_core_version })
          : t("admin.system_limits.check_now_up_to_date"),
      });
    } catch (err) {
      setCheckResult({ ok: false, text: err instanceof Error ? err.message : t("admin.system_limits.check_now_error") });
    } finally {
      setChecking(false);
    }
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    if (saving) return;

    const parsed: Partial<LimitsSettings> = {};
    for (const f of FIELDS) {
      const n = parseInt(inputs[f.key], 10);
      if (isNaN(n)) {
        setMsg({ ok: false, text: t("admin.system_limits.validation_error") });
        return;
      }
      // 0 is a valid "unlimited" value for byte caps and any field marked
      // allowZero (currently just chat_rpm_limit); every other kind
      // (counts, timeouts, intervals) requires a real positive value - see
      // AdminLimitsHandler's own two validation loops on the backend.
      if (f.kind === "byte" || f.allowZero ? n < 0 : n <= 0) {
        setMsg({ ok: false, text: t("admin.system_limits.validation_error") });
        return;
      }
      parsed[f.key] = n;
    }
    if (weekdayInput.size === 0) {
      setMsg({ ok: false, text: t("admin.system_limits.core_update_check_weekdays_error") });
      return;
    }
    parsed.core_update_check_weekdays = Array.from(weekdayInput).sort().join(",");
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(timeInput)) {
      setMsg({ ok: false, text: t("admin.system_limits.core_update_check_time_error") });
      return;
    }
    parsed.core_update_check_time = timeInput;

    setSaving(true);
    setMsg(null);
    try {
      const result = await adminPatchLimitsSettings(parsed as LimitsSettings);
      setSettings(result);
      setInputs(Object.fromEntries(FIELDS.map((f) => [f.key, String(result[f.key])])));
      setWeekdayInput(new Set(
        result.core_update_check_weekdays.split(",").map((v) => parseInt(v, 10)).filter((n) => !isNaN(n)),
      ));
      setTimeInput(result.core_update_check_time);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system_limits.save_error") });
    } finally {
      setSaving(false);
    }
  }

  const visibleFields = FIELDS.filter((f) => f.tab === activeTab);

  function renderField(f: (typeof FIELDS)[number]) {
    switch (f.kind) {
      case "byte":
        return (
          <ByteField key={f.key} fieldKey={f.key} bytesValue={inputs[f.key] ?? ""}
            unit={units[f.key] ?? "B"}
            onBytesChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))}
            onUnitChange={(u) => setUnits((prev) => ({ ...prev, [f.key]: u }))}
            t={t} />
        );
      case "ms":
        return (
          <SecondsField key={f.key} fieldKey={f.key} msValue={inputs[f.key] ?? ""}
            onMsChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
        );
      case "minutes":
        return (
          <MinutesField key={f.key} fieldKey={f.key} secondsValue={inputs[f.key] ?? ""}
            onSecondsChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
        );
      case "seconds":
        return (
          <NumberField key={f.key} fieldKey={f.key} value={inputs[f.key] ?? ""}
            onChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t}
            unitLabel={t("admin.system_limits.unit_seconds")} />
        );
      case "count":
        return (
          <NumberField key={f.key} fieldKey={f.key} value={inputs[f.key] ?? ""}
            onChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
        );
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <Link to="/admin/system"
          className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
          <i className="ti ti-arrow-left text-[14px]" />
          {t("admin.system.back")}
        </Link>
        <h1 className="mb-1 text-xl font-semibold">{t("admin.system_limits.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.system_limits.subtitle")}</p>

        {msg && (
          <p className={`mb-4 text-sm ${msg.ok ? "text-teal-700 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
            {msg.text}
          </p>
        )}

        <div className="mb-6 flex gap-1 border-b border-gray-200 dark:border-gray-800">
          {TABS.map((tab) => (
            <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm ${
                activeTab === tab.id
                  ? "border-teal-600 font-medium text-teal-700 dark:border-teal-400 dark:text-teal-400"
                  : "border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200"
              }`}>
              <i className={`ti ${tab.icon} text-[14px]`} />
              {t(`admin.system_limits.tab_${tab.id}`)}
            </button>
          ))}
        </div>

        <form onSubmit={handleSave} className="space-y-8">
          {activeTab === "updates" ? (
            <Group title={t("admin.system_limits.tab_updates")}>
              <div>
                <label className="mb-2 block text-xs text-gray-500 dark:text-gray-400">
                  {t("admin.system_limits.core_update_check_weekdays_label")}
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {WEEKDAYS.map((wd) => (
                    <button
                      key={wd.value}
                      type="button"
                      onClick={() => toggleWeekday(wd.value)}
                      className={`rounded-lg border px-3 py-1.5 text-sm ${
                        weekdayInput.has(wd.value)
                          ? "border-teal-500 bg-teal-50 font-medium text-teal-700 dark:border-teal-500 dark:bg-teal-950 dark:text-teal-300"
                          : "border-gray-200 text-gray-500 hover:border-gray-300 dark:border-gray-700 dark:text-gray-400"
                      }`}
                    >
                      {t(`admin.system_limits.weekday_${wd.labelKey}`)}
                    </button>
                  ))}
                </div>
                <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                  {t("admin.system_limits.core_update_check_weekdays_hint")}
                </p>
              </div>

              <div>
                <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
                  {t("admin.system_limits.core_update_check_time_label")}
                </label>
                <input
                  type="time"
                  value={timeInput}
                  onChange={(e) => setTimeInput(e.target.value)}
                  className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                />
                <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                  {t("admin.system_limits.core_update_check_time_hint")}
                </p>
              </div>

              <div className="border-t border-gray-100 pt-4 dark:border-gray-800">
                <button
                  type="button"
                  onClick={handleCheckNow}
                  disabled={checking}
                  className="flex items-center gap-2 rounded-md border border-gray-200 px-3 py-2 text-sm font-medium text-gray-700 hover:border-teal-400 hover:text-teal-700 disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:border-teal-600 dark:hover:text-teal-400"
                >
                  <i className={`ti ${checking ? "ti-loader-2 animate-spin" : "ti-refresh"} text-[14px]`} />
                  {checking ? t("common.loading") : t("admin.system_limits.check_now_button")}
                </button>
                {checkResult && (
                  <p className={`mt-2 text-sm ${checkResult.ok ? "text-teal-700 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
                    {checkResult.text}
                  </p>
                )}
              </div>
            </Group>
          ) : (
            <Group title={t(`admin.system_limits.tab_${activeTab}`)}>
              {visibleFields.map((f) => renderField(f))}
            </Group>
          )}

          <div className="flex justify-end">
            <button type="submit" disabled={saving || !dirty}
              className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400">
              {saved ? t("admin.system_limits.saved") : saving ? t("common.saving") : t("common.save")}
            </button>
          </div>
        </form>
      </div>
    </AppShell>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <p className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {title}
      </p>
      <div className="space-y-4 rounded-2xl border border-gray-200 bg-white px-4 py-4 dark:border-gray-800 dark:bg-gray-900">
        {children}
      </div>
    </div>
  );
}

function NumberField({
  fieldKey,
  value,
  onChange,
  t,
  unitLabel,
}: {
  fieldKey: keyof LimitsSettings;
  value: string;
  onChange: (v: string) => void;
  t: (key: string) => string;
  // Optional inline unit suffix (e.g. "seconds") for fields whose backend
  // value is already in a human-friendly unit - unlike geo_timeout_ms
  // (SecondsField above), these timeouts/intervals are stored in seconds
  // directly (no ms/browser-API constraint at the point of use), so no
  // canonical-unit conversion is needed, just a label.
  unitLabel?: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
        {t(`admin.system_limits.${fieldKey}_label`)}
      </label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          min={0}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full flex-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
        />
        {unitLabel && <span className="text-sm text-gray-500 dark:text-gray-400">{unitLabel}</span>}
      </div>
      <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
        {t(`admin.system_limits.${fieldKey}_hint`)}
      </p>
    </div>
  );
}

function ByteField({
  fieldKey,
  bytesValue,
  unit,
  onBytesChange,
  onUnitChange,
  t,
}: {
  fieldKey: keyof LimitsSettings;
  bytesValue: string;
  unit: ByteUnit;
  onBytesChange: (v: string) => void;
  onUnitChange: (u: ByteUnit) => void;
  t: (key: string) => string;
}) {
  const factor = UNIT_FACTORS[unit];
  const numBytes = Number(bytesValue);
  const displayValue = bytesValue !== "" && !isNaN(numBytes)
    ? String(parseFloat((numBytes / factor).toFixed(6)))
    : bytesValue;

  function handleNumberChange(v: string) {
    if (v === "") { onBytesChange(""); return; }
    const n = parseFloat(v);
    if (isNaN(n)) { onBytesChange(v); return; }
    onBytesChange(String(Math.round(n * factor)));
  }

  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
        {t(`admin.system_limits.${fieldKey}_label`)}
      </label>
      <div className="flex gap-2">
        <input
          type="number"
          min={0}
          value={displayValue}
          onChange={(e) => handleNumberChange(e.target.value)}
          className="w-full flex-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
        />
        <select
          value={unit}
          onChange={(e) => onUnitChange(e.target.value as ByteUnit)}
          className="rounded-lg border border-gray-200 bg-white px-2 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
        >
          <option value="B">{t("admin.system_limits.unit_bytes")}</option>
          <option value="KB">KB</option>
          <option value="MB">MB</option>
        </select>
      </div>
      <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
        {t(`admin.system_limits.${fieldKey}_hint`)}
      </p>
    </div>
  );
}

// Stores/sends the canonical value in milliseconds (matching the backend's
// geo_timeout_ms and the browser's native
// navigator.geolocation.getCurrentPosition() timeout option exactly, no
// conversion at the point of use in Home.tsx), but displays and edits it in
// seconds - same "canonical unit + friendlier display" split as ByteField
// above, just with a fixed unit instead of a selector since seconds is the
// only sensible display unit for a value in the single-digit-second range.
const MS_PER_SECOND = 1000;

function SecondsField({
  fieldKey,
  msValue,
  onMsChange,
  t,
}: {
  fieldKey: keyof LimitsSettings;
  msValue: string;
  onMsChange: (v: string) => void;
  t: (key: string) => string;
}) {
  const numMs = Number(msValue);
  const displayValue = msValue !== "" && !isNaN(numMs)
    ? String(parseFloat((numMs / MS_PER_SECOND).toFixed(3)))
    : msValue;

  function handleNumberChange(v: string) {
    if (v === "") { onMsChange(""); return; }
    const n = parseFloat(v);
    if (isNaN(n)) { onMsChange(v); return; }
    onMsChange(String(Math.round(n * MS_PER_SECOND)));
  }

  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
        {t(`admin.system_limits.${fieldKey}_label`)}
      </label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          min={0}
          step={0.1}
          value={displayValue}
          onChange={(e) => handleNumberChange(e.target.value)}
          className="w-full flex-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
        />
        <span className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system_limits.unit_seconds")}</span>
      </div>
      <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
        {t(`admin.system_limits.${fieldKey}_hint`)}
      </p>
    </div>
  );
}

// Stores/sends the canonical value in seconds (matching what the backend's
// time.Duration-based timeouts/tickers actually use, e.g.
// store.SyncInterval, modules.InstallDownloadTimeoutSeconds), but displays
// and edits it in minutes - same split as SecondsField above, just one
// level up: these two fields (registry sync interval, module download
// timeout) sit in the minutes-to-hour range, where a raw seconds count
// (3600, 300) is harder to read at a glance than "60" / "5".
const SECONDS_PER_MINUTE = 60;

function MinutesField({
  fieldKey,
  secondsValue,
  onSecondsChange,
  t,
}: {
  fieldKey: keyof LimitsSettings;
  secondsValue: string;
  onSecondsChange: (v: string) => void;
  t: (key: string) => string;
}) {
  const numSeconds = Number(secondsValue);
  const displayValue = secondsValue !== "" && !isNaN(numSeconds)
    ? String(parseFloat((numSeconds / SECONDS_PER_MINUTE).toFixed(3)))
    : secondsValue;

  function handleNumberChange(v: string) {
    if (v === "") { onSecondsChange(""); return; }
    const n = parseFloat(v);
    if (isNaN(n)) { onSecondsChange(v); return; }
    onSecondsChange(String(Math.round(n * SECONDS_PER_MINUTE)));
  }

  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
        {t(`admin.system_limits.${fieldKey}_label`)}
      </label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          min={0}
          step={0.1}
          value={displayValue}
          onChange={(e) => handleNumberChange(e.target.value)}
          className="w-full flex-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
        />
        <span className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system_limits.unit_minutes")}</span>
      </div>
      <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
        {t(`admin.system_limits.${fieldKey}_hint`)}
      </p>
    </div>
  );
}
