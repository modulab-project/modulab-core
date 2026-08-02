import { useCallback, useEffect, useRef, useState } from "react";
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

  // Per-toast auto-dismiss timers, keyed by toast id, so they can be
  // cleared individually (once the toast fires) and in bulk on unmount -
  // without this a timer that outlives its owning component would call
  // setToasts() on an unmounted hook instance.
  const timers = useRef<Map<number, ReturnType<typeof window.setTimeout>>>(new Map());

  useEffect(() => {
    const timerMap = timers.current;
    return () => {
      timerMap.forEach((timer) => window.clearTimeout(timer));
      timerMap.clear();
    };
  }, []);

  const push = useCallback((t: Omit<ToastItem, "id">) => {
    const id = nextToastID++;
    setToasts((prev) => [...prev, { ...t, id }]);
    const timer = window.setTimeout(() => {
      timers.current.delete(id);
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, TOAST_DURATION_MS);
    timers.current.set(id, timer);
  }, []);

  return { toasts, push };
}
