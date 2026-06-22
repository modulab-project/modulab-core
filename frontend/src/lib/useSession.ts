import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getMe, type Session } from "./api";
import { clearSessionToken, getSessionToken } from "./session";

// Shared guard for every page that requires a fully-approved session -
// currently Home ("/") and ProfilePage ("/profile"), both of which had this
// exact effect duplicated before this hook existed. Redirects to /login if
// there is no token or it turns out to be invalid/expired, to /pending if
// the resolved session's role is still "pending" (see backend/internal/
// auth.CallbackHandler's two-gate access model - a pending session is real,
// just not allowed past that one screen), and otherwise hands back the
// resolved session for the page to render with.
export function useAuthenticatedSession(): { session: Session | null; loading: boolean } {
  const navigate = useNavigate();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) {
      navigate("/login", { replace: true });
      return;
    }
    getMe(token)
      .then((s) => {
        if (s.role === "pending") {
          navigate("/pending", { replace: true });
          return;
        }
        setSession(s);
        setLoading(false);
      })
      .catch(() => {
        clearSessionToken();
        navigate("/login", { replace: true });
      });
  }, [navigate]);

  return { session, loading };
}
