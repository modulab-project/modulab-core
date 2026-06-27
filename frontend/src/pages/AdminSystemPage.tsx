import { useEffect, useRef, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  getSystemStatus,
  smtpStatus as fetchSmtpStatus,
  searxngStatus as fetchSearxngStatus,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system — super-admin hub. Shows all system-config areas as cards
// with current status. Each card links to its own dedicated sub-page.
export default function AdminSystemPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [oidcConfigured, setOidcConfigured] = useState(false);
  const [dnsConfigured, setDnsConfigured] = useState(false);
  const [groupPrefix, setGroupPrefix] = useState<string | null>(null);
  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [searxngConfigured, setSearxngConfigured] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;

    const token = getSessionToken();
    if (!token) return;

    Promise.all([
      getSystemStatus(token),
      fetchSmtpStatus(token),
      fetchSearxngStatus(token),
    ])
      .then(([sys, smtp, searxng]) => {
        setOidcConfigured(sys.oidc.configured);
        setDnsConfigured(sys.dns_challenge.configured);
        setGroupPrefix(sys.group_prefix ?? null);
        setSmtpConfigured(smtp.configured);
        setSearxngConfigured(searxng.configured);
      })
      .catch(() => setLoadError(t("admin.system.load_error")));
  }, [session, navigate, t]);

  if (loading || !session || session.role !== "super-admin") return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <div className="mb-8">
          <h1 className="text-xl font-semibold mb-1">{t("admin.system.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system.hub_subtitle")}</p>
        </div>

        {loadError && (
          <p className="mb-6 text-sm text-red-600 dark:text-red-400">{loadError}</p>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {/* Group prefix — read-only, no sub-page */}
          <div className="rounded-xl border border-gray-200 p-4 dark:border-gray-800">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <i className="ti ti-tag text-[18px] text-gray-400" />
                <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  {t("admin.system.group_prefix_title")}
                </span>
              </div>
            </div>
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 mb-2">
              {t("admin.system.group_prefix_hint")}
            </p>
            <div className="rounded-lg border border-gray-100 bg-gray-50 px-2.5 py-1.5 text-xs font-mono text-gray-700 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-300">
              {groupPrefix || <span className="text-gray-400 dark:text-gray-600">{t("admin.system.not_configured")}</span>}
            </div>
          </div>

          {/* OIDC */}
          <ConfigCard
            icon="ti-id"
            title={t("admin.system.oidc_title")}
            description={t("admin.system.oidc_card_desc")}
            configured={oidcConfigured}
            href="/admin/system/oidc"
            t={t}
          />

          {/* DNS-Challenge */}
          <ConfigCard
            icon="ti-certificate"
            title={t("admin.system.dns_title")}
            description={t("admin.system.dns_card_desc")}
            configured={dnsConfigured}
            href="/admin/system/dns"
            t={t}
          />

          {/* SMTP */}
          <ConfigCard
            icon="ti-mail"
            title={t("admin.smtp.title")}
            description={t("admin.smtp.subtitle")}
            configured={smtpConfigured}
            href="/admin/system/smtp"
            t={t}
          />

          {/* SearXNG */}
          <ConfigCard
            icon="ti-search"
            title={t("admin.searxng.title")}
            description={t("admin.system.searxng_card_desc")}
            configured={searxngConfigured}
            href="/admin/system/searxng"
            t={t}
          />

          {/* KI-Anbieter — always links to /admin/ai */}
          <Link
            to="/admin/ai"
            className="group flex flex-col rounded-xl border border-gray-200 p-4 transition-colors hover:border-teal-400 hover:bg-teal-50/40 dark:border-gray-800 dark:hover:border-teal-700 dark:hover:bg-teal-950/30"
          >
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-center gap-2.5">
                <i className="ti ti-sparkles text-[18px] text-gray-400 group-hover:text-teal-600 dark:group-hover:text-teal-400" />
                <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  {t("admin.ai.title")}
                </span>
              </div>
              <i className="ti ti-chevron-right flex-none text-gray-300 group-hover:text-teal-500 dark:text-gray-600 dark:group-hover:text-teal-400" />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
              {t("admin.system.ai_card_desc")}
            </p>
          </Link>
        </div>
      </div>
    </AppShell>
  );
}

function ConfigCard({
  icon,
  title,
  description,
  configured,
  href,
  t,
}: {
  icon: string;
  title: string;
  description: string;
  configured: boolean;
  href: string;
  t: (key: string) => string;
}) {
  return (
    <Link
      to={href}
      className="group flex flex-col rounded-xl border border-gray-200 p-4 transition-colors hover:border-teal-400 hover:bg-teal-50/40 dark:border-gray-800 dark:hover:border-teal-700 dark:hover:bg-teal-950/30"
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2.5">
          <i className={`ti ${icon} text-[18px] text-gray-400 group-hover:text-teal-600 dark:group-hover:text-teal-400`} />
          <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">{title}</span>
        </div>
        <i className="ti ti-chevron-right flex-none text-gray-300 group-hover:text-teal-500 dark:text-gray-600 dark:group-hover:text-teal-400" />
      </div>
      <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">{description}</p>
      <div className="mt-auto flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 rounded-full ${configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`} />
        <span className="text-[11px] text-gray-400 dark:text-gray-500">
          {configured ? t("admin.smtp.status_configured") : t("admin.smtp.status_not_configured")}
        </span>
      </div>
    </Link>
  );
}
