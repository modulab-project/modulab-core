import { useCallback, useState } from "react";
import type { ToastItem } from "../components/Toast";

let nextToastID = 1;

// Auto-dismiss delay - long enough to read a one-line message, short
// enough not to pile up if several events arrive in quick succession
// (e.g. several admins approving people back-to-back).
const TOAST_DURATION_MS = 6_000;

// useToasts gives a page (AppShell, Pending.tsx) a small in-memory toast
// queue: push() adds one, it disappears on its own after
// TOAST_DURATION_MS, and the returned `toasts` array is what
// <ToastStack> (components/Toast.tsx) actually renders. Not React context /
// a provider - every current caller owns and renders its own stack
// directly, since nothing today needs a toast to be pushed from one part of
// the tree and shown in another.
//
// Split out of components/Toast.tsx (which now only exports the ToastStack
// component) so that file only exports components, keeping react-refresh
// fast-refresh-friendly.
export function useToasts(): { toasts: ToastItem[]; push: (t: Omit<ToastItem, "id">) => void } {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const push = useCallback((t: Omit<ToastItem, "id">) => {
    const id = nextToastID++;
    setToasts((prev) => [...prev, { ...t, id }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, TOAST_DURATION_MS);
  }, []);

  return { toasts, push };
}
