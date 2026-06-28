import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import SetupWizard from "./pages/SetupWizard";
import AuthComplete from "./pages/AuthComplete";
import Login from "./pages/Login";
import Pending from "./pages/Pending";
import Home from "./pages/Home";
import ProfilePage from "./pages/ProfilePage";
import UserFeedsPage from "./pages/UserFeedsPage";
import UserSearchPrefsPage from "./pages/UserSearchPrefsPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import AdminFeedsPage from "./pages/AdminFeedsPage";
import AdminSystemOIDCPage from "./pages/AdminSystemOIDCPage";
import AdminSystemDNSPage from "./pages/AdminSystemDNSPage";
import AdminSystemSmtpPage from "./pages/AdminSystemSmtpPage";
import AdminSystemSearxngPage from "./pages/AdminSystemSearxngPage";
import AdminAIPage from "./pages/AdminAIPage";
import AdminQuickLinksPage from "./pages/AdminQuickLinksPage";
import AdminSystemPage from "./pages/AdminSystemPage";
import AdminAuditPage from "./pages/AdminAuditPage";
import UserAIKeysPage from "./pages/UserAIKeysPage";
import StorePage from "./pages/StorePage";
import ModulesPage from "./pages/ModulesPage";
import AdminModulesPage from "./pages/AdminModulesPage";
import Footer from "./components/Footer";

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
    <Routes>
      <Route path="/" element={<Home />} />
      {/* Like Home, owns its own full-viewport header - no WithFooter here. */}
      <Route path="/profile" element={<ProfilePage />} />
      <Route path="/user/feeds" element={<UserFeedsPage />} />
      <Route path="/user/search-prefs" element={<UserSearchPrefsPage />} />
      <Route path="/user/ai-keys" element={<UserAIKeysPage />} />
      <Route path="/admin/modules" element={<AdminModulesPage />} />
      <Route path="/admin/modules/store" element={<StorePage />} />
      <Route path="/admin/modules/installed" element={<ModulesPage />} />
      <Route path="/admin/users" element={<AdminUsersPage />} />
      {/* Legacy direct routes redirect to the sub-pages under /admin/system */}
      <Route path="/admin/smtp" element={<Navigate to="/admin/system/smtp" replace />} />
      <Route path="/admin/searxng" element={<Navigate to="/admin/system/searxng" replace />} />
      <Route path="/admin/feeds" element={<AdminFeedsPage />} />
      <Route path="/admin/ai" element={<Navigate to="/admin/system/ai" replace />} />
      <Route path="/admin/system/ai" element={<AdminAIPage />} />
      <Route path="/admin/quick-links" element={<AdminQuickLinksPage />} />
      <Route path="/admin/system" element={<AdminSystemPage />} />
      <Route path="/admin/system/oidc" element={<AdminSystemOIDCPage />} />
      <Route path="/admin/system/dns" element={<AdminSystemDNSPage />} />
      <Route path="/admin/system/smtp" element={<AdminSystemSmtpPage />} />
      <Route path="/admin/system/searxng" element={<AdminSystemSearxngPage />} />
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
  );
}

function WithFooter({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <div className="flex-1">{children}</div>
      <Footer />
    </div>
  );
}
