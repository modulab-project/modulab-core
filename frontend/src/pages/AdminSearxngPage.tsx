import { useEffect } from "react";
import { useNavigate } from "react-router";

// "/admin/searxng" was the very first (pre-App.tsx-redirect) path for the
// SearXNG config page, dead/unrouted since App.tsx started redirecting
// "/admin/searxng" -> "/admin/system/searxng" itself. Kept as a plain
// redirect stub (rather than deleted) because this file lives in an
// iCloud-synced folder where file deletion from here isn't reliable - see
// AdminSystemSearxngPage.tsx for the real, still-routed page, now rebuilt
// as a multi-provider search settings page (internal/search backend).
export default function AdminSearxngPage() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate("/admin/system/searxng", { replace: true });
  }, [navigate]);
  return null;
}
