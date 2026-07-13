import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { adminGetLimitsSettings, adminPatchLimitsSettings, type LimitsSettings } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system/limits — consolidates every cross-cutting operational limit
// that used to be a hardcoded Go constant (request body size, module/ZIP/
// OPML upload caps, rate limits, Deno worker pool size). See
// backend/internal/adminapi/limits.go's doc comment for the incident that
// prompted this (module photo uploads silently capped at ~1 MB by a global
// middleware limit nested outside the module's own, larger limit).
//
// All 15 fields are backed by raw byte/count values in `inputs`, matching
// exactly what the backend stores and what the hint text documents. The
// "uploads" group (byte limits) additionally gets a unit selector (Bytes/
// KB/MB) purely as a display/edit convenience — `inputs` always holds the
// canonical byte string, converted on the way in and out. The unit choice
// is not persisted anywhere (not localStorage, not the backend); it's just
// re-derived from the byte value each time settings are (re)loaded. The
// "timeouts" group's six fields are stored in seconds directly on the
// backend (no ms/browser-API constraint at their point of use, unlike
// geo_timeout_ms), so they render as a plain NumberField with a "seconds"
// suffix rather than needing SecondsField's ms↔s conversion.
const FIELDS: Array<{ key: keyof LimitsSettings; group: "uploads" | "rate_limits" | "performance" | "timeouts" }> = [
  { key: "max_body_bytes", group: "uploads" },
  { key: "max_upload_body_bytes", group: "uploads" },
  { key: "max_module_zip_bytes", group: "uploads" },
  { key: "max_opml_upload_bytes", group: "uploads" },
  { key: "auth_rate_limit_max", group: "rate_limits" },
  { key: "ai_chat_ip_rate_limit_max", group: "rate_limits" },
  { key: "global_rate_limit_max", group: "rate_limits" },
  { key: "deno_conn_pool_size", group: "performance" },
  { key: "geo_timeout_ms", group: "performance" },
  { key: "ai_provider_timeout_seconds", group: "timeouts" },
  { key: "searxng_search_timeout_seconds", group: "timeouts" },
  { key: "news_fetch_timeout_seconds", group: "timeouts" },
  { key: "store_sync_interval_seconds", group: "timeouts" },
  { key: "store_github_api_timeout_seconds", group: "timeouts" },
  { key: "modules_install_download_timeout_seconds", group: "timeouts" },
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
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    const token = getSessionToken();
    if (!token) return;
    adminGetLimitsSettings(token)
      .then((s) => {
        setSettings(s);
        setInputs(Object.fromEntries(FIELDS.map((f) => [f.key, String(s[f.key])])));
        setUnits(Object.fromEntries(
          FIELDS.filter((f) => f.group === "uploads").map((f) => [f.key, detectUnit(Number(s[f.key]))]),
        ));
      })
      .catch(() => setMsg({ ok: false, text: t("admin.system_limits.load_error") }));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  const dirty = settings !== null && FIELDS.some((f) => inputs[f.key] !== String(settings[f.key]));

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token || saving) return;

    const parsed: Partial<LimitsSettings> = {};
    for (const f of FIELDS) {
      const n = parseInt(inputs[f.key], 10);
      if (isNaN(n)) {
        setMsg({ ok: false, text: t("admin.system_limits.validation_error") });
        return;
      }
      const isByteLimit = f.group === "uploads";
      if (isByteLimit ? n < 0 : n <= 0) {
        setMsg({ ok: false, text: t("admin.system_limits.validation_error") });
        return;
      }
      parsed[f.key] = n;
    }

    setSaving(true);
    setMsg(null);
    try {
      const result = await adminPatchLimitsSettings(token, parsed as LimitsSettings);
      setSettings(result);
      setInputs(Object.fromEntries(FIELDS.map((f) => [f.key, String(result[f.key])])));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : t("admin.system_limits.save_error") });
    } finally {
      setSaving(false);
    }
  }

  const uploadsFields = FIELDS.filter((f) => f.group === "uploads");
  const rateLimitFields = FIELDS.filter((f) => f.group === "rate_limits");
  const performanceFields = FIELDS.filter((f) => f.group === "performance");
  const timeoutFields = FIELDS.filter((f) => f.group === "timeouts");

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

        <form onSubmit={handleSave} className="space-y-8">
          <Group title={t("admin.system_limits.group_uploads")}>
            {uploadsFields.map((f) => (
              <ByteField key={f.key} fieldKey={f.key} bytesValue={inputs[f.key] ?? ""}
                unit={units[f.key] ?? "B"}
                onBytesChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))}
                onUnitChange={(u) => setUnits((prev) => ({ ...prev, [f.key]: u }))}
                t={t} />
            ))}
          </Group>
          <Group title={t("admin.system_limits.group_rate_limits")}>
            {rateLimitFields.map((f) => (
              <NumberField key={f.key} fieldKey={f.key} value={inputs[f.key] ?? ""}
                onChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
            ))}
          </Group>
          <Group title={t("admin.system_limits.group_performance")}>
            {performanceFields.map((f) =>
              f.key === "geo_timeout_ms" ? (
                <SecondsField key={f.key} fieldKey={f.key} msValue={inputs[f.key] ?? ""}
                  onMsChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
              ) : (
                <NumberField key={f.key} fieldKey={f.key} value={inputs[f.key] ?? ""}
                  onChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t} />
              ),
            )}
          </Group>
          <Group title={t("admin.system_limits.group_timeouts")}>
            {timeoutFields.map((f) => (
              <NumberField key={f.key} fieldKey={f.key} value={inputs[f.key] ?? ""}
                onChange={(v) => setInputs((prev) => ({ ...prev, [f.key]: v }))} t={t}
                unitLabel={t("admin.system_limits.unit_seconds")} />
            ))}
          </Group>

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
