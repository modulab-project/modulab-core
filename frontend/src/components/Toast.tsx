import { useCallback, useState } from "react";

// Minimal toast stack for spec section 3.5's real-time notifications
// (useNotificationEvents, lib/useEvents.ts) - no separate library, since
// the only thing needed is "show a short-lived message in the corner,
// optionally with one action link", which is a handful of lines on top of
// what AppShell.tsx already has for its slide panels.
export interface ToastItem {
  id: number;
  message: string;
  actionLabel?: string;
  onAction?: () => void;
}

let nextToastID = 1;

// Auto-dismiss delay - long enough to read a one-line message, short
// enough not to pile up if several events arrive in quick succession
// (e.g. several admins approving people back-to-back).
const TOAST_DURATION_MS = 6_000;

// useToasts gives a page (AppShell, Pending.tsx) a small in-memory toast
// queue: push() adds one, it disappears on its own after
// TOAST_DURATION_MS, and the returned `toasts` array is what
// <ToastStack> below actually renders. Not React context / a provider -
// every current caller owns and renders its own stack directly, since
// nothing today needs a toast to be pushed from one part of the tree and
// shown in another.
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

export function ToastStack({ toasts }: { toasts: ToastItem[] }) {
  if (toasts.length === 0) {
    return null;
  }
  return (
    <div className="fixed bottom-14 left-1/2 z-30 flex w-full max-w-sm -translate-x-1/2 flex-col gap-2 px-3">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="flex items-start justify-between gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm shadow-lg dark:border-gray-800 dark:bg-gray-900"
        >
          <span className="min-w-0 whitespace-pre-wrap break-words">{t.message}</span>
          {t.actionLabel && t.onAction && (
            <button
              type="button"
              onClick={t.onAction}
              className="flex-none text-xs font-medium text-teal-600 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
            >
              {t.actionLabel}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
