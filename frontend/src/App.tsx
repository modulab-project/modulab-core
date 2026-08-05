import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router";
import Footer from "./components/Footer";

// Every page is route-split via React.lazy so the initial bundle only ships
// the app shell + router, not every admin/user page up front. Suspense
// fallback is intentionally minimal (blank) - on a self-hosted, low-traffic
// setup the flash is negligible and this keeps the pattern uniform for any
// future page (no per-page judgment call about whether it "deserves"
// splitting).
const SetupWizard = lazy(() => import("./pages/SetupWizard"));
const AuthComplete = lazy(() => import("./pages/AuthComplete"));
const Login = lazy(() => import("./pages/Login"));
const Pending = lazy(() => import("./pages/Pending"));
const Home = lazy(() => import("./pages/Home"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const UserFeedsPage = lazy(() => import("./pages/UserFeedsPage"));
const UserSearchPrefsPage = lazy(() => import("./pages/UserSearchPrefsPage"));
const AdminUsersPage = lazy(() => import("./pages/AdminUsersPage"));
const AdminFeedsPage = lazy(() => import("./pages/AdminFeedsPage"));
const AdminSystemOIDCPage = lazy(() => import("./pages/AdminSystemOIDCPage"));
const AdminSystemSmtpPage = lazy(() => import("./pages/AdminSystemSmtpPage"));
const AdminSystemGeoIPPage = lazy(() => import("./pages/AdminSystemGeoIPPage"));
const AdminSystemSearchPage = lazy(() => import("./pages/AdminSystemSearchPage"));
const AdminAIPage = lazy(() => import("./pages/AdminAIPage"));
const AdminSystemLimitsPage = lazy(() => import("./pages/AdminSystemLimitsPage"));
const AdminSystemGeneralPage = lazy(() => import("./pages/AdminSystemGeneralPage"));
const AdminQuickLinksPage = lazy(() => import("./pages/AdminQuickLinksPage"));
const AdminSystemInfoPage = lazy(() => import("./pages/AdminSystemInfoPage"));
const AdminSecurityInfoPage = lazy(() => import("./pages/AdminSecurityInfoPage"));
const AdminAuditPage = lazy(() => import("./pages/AdminAuditPage"));
const UserAIKeysPage = lazy(() => import("./pages/UserAIKeysPage"));
const StorePage = lazy(() => import("./pages/StorePage"));
const ModulesPage = lazy(() => import("./pages/ModulesPage"));
const ModulePage = lazy(() => import("./pages/ModulePage"));

// Two different page shapes share this router:
//   - SetupWizard / AuthComplete / Login / Pending are short, scrollable
//     documents - they get the shared Footer (copyright/version/links)
//     appended below them via WithFooter, like any ordinary page.
//   - Home ("/"), ProfilePage ("/profile"), and AdminUsersPage
//     ("/admin/users") own a full-viewport layout via AppShell (see
//     Home.tsx's top-of-file comment) - wrapping any of them in another
//     footer below would just stack two footers. AdminUsersPage gates
//     itself on role client-side (and the backend gates it for real via
//     requireAdmin) rather than this router needing to know about roles.
//
// The wildcard route still goes to /setup, not straight to /login: that
// is intentional, not leftover from before /login existed. SetupWizard
// checks /healthz's setup_completed on mount and immediately redirects to
// /login itself once the wizard is done, so this is one extra redirect
// hop, not a dead end - kept this way so there is exactly one place
// (SetupWizard) that owns "is this instance's wizard done yet".
export default function App() {
  return (
    <Suspense fallback={null}>
      <Routes>
        <Route path="/" element={<Home />} />
        {/* Like Home, owns its own full-viewport header - no WithFooter here. */}
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="/user/feeds" element={<UserFeedsPage />} />
        <Route path="/user/search-prefs" element={<UserSearchPrefsPage />} />
        <Route path="/user/ai-keys" element={<UserAIKeysPage />} />
        {/* Installed module pages — one route per module, using the module name */}
        <Route path="/modules/:moduleName" element={<ModulePage />} />
        <Route path="/admin/modules/store" element={<StorePage />} />
        <Route path="/admin/modules/installed" element={<ModulesPage />} />
        <Route path="/admin/users" element={<AdminUsersPage />} />
        {/* Legacy direct routes redirect to the sub-pages under /admin/system */}
        <Route path="/admin/smtp" element={<Navigate to="/admin/system/smtp" replace />} />
        <Route path="/admin/searxng" element={<Navigate to="/admin/system/search" replace />} />
        <Route path="/admin/feeds" element={<AdminFeedsPage />} />
        <Route path="/admin/ai" element={<Navigate to="/admin/system/ai" replace />} />
        <Route path="/admin/system/ai" element={<AdminAIPage />} />
        <Route path="/admin/system/limits" element={<AdminSystemLimitsPage />} />
        <Route path="/admin/system/general" element={<AdminSystemGeneralPage />} />
        <Route path="/admin/quick-links" element={<AdminQuickLinksPage />} />
        <Route path="/admin/system/info" element={<AdminSystemInfoPage />} />
        <Route path="/admin/security/info" element={<AdminSecurityInfoPage />} />
        <Route path="/admin/system/oidc" element={<AdminSystemOIDCPage />} />
        <Route path="/admin/system/smtp" element={<AdminSystemSmtpPage />} />
        <Route path="/admin/system/geoip" element={<AdminSystemGeoIPPage />} />
        {/* Legacy URL redirect: page was renamed from SearXNG-only to a
            general multi-provider search admin page. */}
        <Route path="/admin/system/searxng" element={<Navigate to="/admin/system/search" replace />} />
        <Route path="/admin/system/search" element={<AdminSystemSearchPage />} />
        <Route path="/admin/audit" element={<AdminAuditPage />} />
        <Route
          path="/setup"
          element={
            <WithFooter>
              <SetupWizard />
            </WithFooter>
          }
        />
        <Route
          path="/auth/complete"
          element={
            <WithFooter>
              <AuthComplete />
            </WithFooter>
          }
        />
        <Route
          path="/login"
          element={
            <WithFooter>
              <Login />
            </WithFooter>
          }
        />
        <Route
          path="/pending"
          element={
            <WithFooter>
              <Pending />
            </WithFooter>
          }
        />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    </Suspense>
  );
}

function WithFooter({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <div className="flex-1">{children}</div>
      <Footer />
    </div>
  );
}
