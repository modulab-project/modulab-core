import { useEffect, useState } from "react";
import { getMe, loginRedirectUrl, type Session } from "./api";
import { acquireLoginLock, isLoginLockHeld, onLoginLockChange } from "./loginLock";

// Shared by every place in the app that can trigger a full OIDC round-trip
// (window.location.href = loginRedirectUrl()) - currently Login.tsx's main
// button, SetupWizard.tsx's step 4 super-admin login, and the inline
// "please log in again" links AdminUsersPage.tsx/ProfilePage.tsx show when
// a sensitive action is rejected for needing a more recent login
// (backend's requireRecentLogin). Pulled out of Login.tsx (2026-07-16) once
// it became clear the same "don't let two tabs both mint a session" problem
// applies at all four call sites, not just the main login screen - see
// loginLock.ts's top-of-file comment for why the coordination itself has to
// go through localStorage rather than something simpler.
//
// onAlreadyAuthenticated fires once this tab discovers - via the lock being
// released by whichever tab held it - that a login has just succeeded
// elsewhere, and getMe() now confirms this tab's cookie is valid too (the
// httpOnly cookie is shared by every tab of the same browser, so nothing
// else needs to happen for this tab to be logged in as well). It receives
// the freshly-fetched Session so a caller that needs to branch on role
// (e.g. SetupWizard's "is this actually the super-admin?" check) doesn't
// have to make its own second getMe() call - note this session came from
// *this* tab's fetch, not sessionStorage, since AuthComplete's stashed
// auth-result fragment is per-tab (sessionStorage) and never reaches a tab
// that didn't itself run the OIDC round-trip. Defaults to a full reload,
// a safe fallback for any caller that doesn't need anything fancier than
// "pick up the newly-valid session".
export function useLoginRedirect(onAlreadyAuthenticated?: (session: Session) => void) {
  const [waiting, setWaiting] = useState(false);

  useEffect(() => {
    if (!isLoginLockHeld()) {
      return;
    }
    // Mount-time read of an external store (localStorage's lock) - same
    // justification as Login.tsx's consumeAuthResult() effect, not state
    // derived from props/other state, so it can't cascade.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setWaiting(true);
    const unsubscribe = onLoginLockChange(() => {
      getMe()
        .then((session) => {
          if (onAlreadyAuthenticated) {
            onAlreadyAuthenticated(session);
          } else {
            window.location.reload();
          }
        })
        .catch(() => {
          // Still not logged in (the other tab's attempt failed, or was
          // abandoned) - fall back to a normal, clickable state.
          setWaiting(false);
        });
    });
    return unsubscribe;
    // eslint-disable-next-line react-hooks/exhaustive-deps -- onAlreadyAuthenticated is expected to be a stable callback per caller; re-subscribing on every render would tear down/rebuild the listener for no reason.
  }, []);

  // Call from a button's onClick (or an intercepted <a> click) to start the
  // OIDC round-trip. Returns nothing - navigation happens synchronously via
  // window.location.href, or `waiting` flips to true if another tab already
  // holds the lock, same as the mount-time check above.
  //
  // options are passed straight through to loginRedirectUrl - AdminUsersPage.tsx/
  // ProfilePage.tsx's "please log in again" links pass { reauth: true,
  // returnPath: <current page> } here; Login.tsx's main button and
  // SetupWizard.tsx's step 4 call this with no options at all, same as
  // before this parameter existed.
  function startLogin(options?: { reauth?: boolean; returnPath?: string }) {
    if (!acquireLoginLock()) {
      setWaiting(true);
      return;
    }
    window.location.href = loginRedirectUrl(options);
  }

  return { waiting, startLogin };
}
