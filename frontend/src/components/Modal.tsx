import { useEffect, useRef, type CSSProperties, type ReactNode } from "react";

// Shared dialog shell for every modal in the app: fixed-inset backdrop +
// centered panel (same Tailwind convention the hand-rolled modals already
// used - see AppShell.tsx's IOSInstallInstructions, the original template
// for this component), click-outside-to-close, Escape-to-close, and a
// standard focus trap (Tab/Shift+Tab cycle within the panel while open,
// focus returns to whatever was focused before the modal opened). No
// createPortal - nothing else in this codebase renders modals through a
// portal, and a `fixed inset-0` panel doesn't need one since it already
// paints above everything via z-index.
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  /** id of the heading element inside `children` that labels this dialog. */
  titleId?: string;
  /** Use instead of titleId when there's no visible heading to point at. */
  ariaLabel?: string;
  children: ReactNode;
  /** Overrides the default panel sizing/styling classes. */
  className?: string;
  /** Inline styles for the panel (e.g. a dynamic max-height). */
  style?: CSSProperties;
}

export function Modal({ open, onClose, titleId, ariaLabel, children, className, style }: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;

    previouslyFocused.current = document.activeElement as HTMLElement | null;

    const panel = panelRef.current;
    const focusable = () =>
      panel
        ? Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
            (el) => el.offsetParent !== null,
          )
        : [];

    // Move focus into the panel on open - the first focusable element if
    // there is one, otherwise the panel itself (tabIndex={-1} below makes
    // that a valid focus target without adding it to the normal tab order).
    const initial = focusable();
    if (initial.length > 0) {
      initial[0].focus();
    } else {
      panel?.focus();
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panel) return;

      const elements = focusable();
      if (elements.length === 0) {
        e.preventDefault();
        return;
      }
      const first = elements[0];
      const last = elements[elements.length - 1];
      const active = document.activeElement as HTMLElement | null;

      if (e.shiftKey) {
        if (active === first || !active || !panel.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (active === last || !active || !panel.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      // Restore focus to whatever had it before the modal opened.
      previouslyFocused.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    // Click-outside-to-close backdrop; the panel below only stops
    // propagation so clicking inside it doesn't also close the modal -
    // neither has real keyboard-actionable semantics of its own (Escape is
    // handled globally above instead).
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/click-events-have-key-events */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ariaLabel ? undefined : titleId}
        aria-label={ariaLabel}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={style}
        className={
          className ??
          "max-h-[85vh] w-full max-w-md overflow-y-auto rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900"
        }
      >
        {children}
      </div>
    </div>
  );
}
