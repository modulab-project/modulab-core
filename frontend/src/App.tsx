import { Navigate, Route, Routes } from "react-router-dom";
import SetupWizard from "./pages/SetupWizard";
import AuthComplete from "./pages/AuthComplete";
import Footer from "./components/Footer";

// Routes mirror spec section 6.4's planned route table - only the two that
// the Setup Wizard (section 6.5) actually needs exist yet. /login, /, and
// the rest of the dashboard land once Phase 2 grows beyond the wizard.
//
// Footer renders on every route (including the brief /auth/complete landing
// page) rather than being duplicated inside each page component.
export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <div className="flex-1">
        <Routes>
          <Route path="/setup" element={<SetupWizard />} />
          <Route path="/auth/complete" element={<AuthComplete />} />
          <Route path="*" element={<Navigate to="/setup" replace />} />
        </Routes>
      </div>
      <Footer />
    </div>
  );
}
