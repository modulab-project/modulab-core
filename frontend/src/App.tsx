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
import AdminSmtpPage from "./pages/AdminSmtpPage";
import AdminFeedsPage from "./pages/AdminFeedsPage";
import AdminSearxngPage from "./pages/AdminSearxngPage";
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
      <Route path="/admin/users" element={<AdminUsersPage />} />
      <Route path="/admin/smtp" element={<AdminSmtpPage />} />
      <Route path="/admin/feeds" element={<AdminFeedsPage />} />
      <Route path="/admin/searxng" element={<AdminSearxngPage />} />
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
