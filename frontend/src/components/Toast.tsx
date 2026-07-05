// Minimal toast stack for spec section 3.5's real-time notifications
// (useNotificationEvents, lib/useEvents.ts) - no separate library, since
// the only thing needed is "show a short-lived message in the corner,
// optionally with one action link", which is a handful of lines on top of
// what AppShell.tsx already has for its slide panels.
//
// The useToasts() hook that produces the `toasts` array below lives in
// lib/toasts.ts, not here - keeping this file to only the ToastStack
// component (plus the plain ToastItem type) is what lets react-refresh
// fast-refresh it cleanly.
export interface ToastItem {
  id: number;
  message: string;
  actionLabel?: string;
  onAction?: () => void;
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
