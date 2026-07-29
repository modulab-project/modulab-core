import type { ButtonHTMLAttributes, ReactNode } from "react";
import { useTranslation } from "react-i18next";

// Shared visual shell for the three "no session yet" pages (Login,
// SetupWizard, Pending) so they look like part of the same product as
// Home.tsx instead of a generic gray Tailwind form. Reuses the exact same
// logo artwork as Home.tsx's header for brand consistency.
//
// Deliberately does NOT render its own footer or manage dark-mode state:
// App.tsx's WithFooter already wraps every page that uses this shell in
// the shared Footer (copyright/version/links), and the "dark" class is
// applied globally before first paint by the inline script in index.html
// (reading the same modulab_theme key AppShell.tsx writes to, including its
// "system" value - see that script's own comment) - this shell just needs
// to respond to that class via dark: variants, not own it.
export function AuthShell({
  title,
  subtitle,
  centerText = false,
  children,
}: {
  title: string;
  subtitle?: string;
  // SetupWizard's steps are left-aligned forms (labels, Back/Next button
  // rows) where a centered heading would look disconnected from the
  // fields below it - Login and Pending have no form at all, just a
  // heading/message/button stack, where centered reads better. Defaults
  // to false (SetupWizard's existing look) so it only needs setting
  // explicitly where it differs.
  centerText?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-[calc(100dvh-77px)] items-center justify-center px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center gap-2.5">
          <Logo />
          <span className="text-[22px] font-semibold tracking-tight text-gray-900 dark:text-gray-100">
            Modu<span className="text-teal-600 dark:text-teal-400">Lab</span>
          </span>
        </div>
        <div className="rounded-2xl border border-gray-200 bg-white px-6 py-8 shadow-sm dark:border-gray-800 dark:bg-gray-900 sm:px-8">
          <h1
            className={`mb-1 text-xl font-semibold text-gray-900 dark:text-gray-100 ${centerText ? "text-center" : ""}`}
          >
            {title}
          </h1>
          <p
            className={`mb-6 min-h-[1.25rem] text-sm text-gray-500 dark:text-gray-400 ${centerText ? "text-center" : ""}`}
          >
            {subtitle}
          </p>
          {children}
        </div>
      </div>
    </div>
  );
}

// Exported so other pages outside the "no session yet" shell - currently
// just ProfilePage.tsx's header - can reuse the exact same artwork instead
// of a third copy-pasted copy of this SVG drifting out of sync over time.
export function Logo({ className = "h-11 w-11" }: { className?: string }) {
  const { t } = useTranslation();
  return (
    <svg viewBox="0 0 130 120" className={className} role="img" aria-label={t("common.logo_alt")}>
      <polygon
        points="95,25 117,37 117,63 95,75 73,63 73,37"
        fill="none"
        stroke="#005f7a"
        strokeWidth="2"
        opacity="0.5"
      />
      <polygon points="35,65 57,77 57,103 35,115 13,103 13,77" fill="#1f2d3d" />
      <polygon points="65,40 87,52 87,78 65,90 43,78 43,52" fill="#0084a8" />
      <path
        d="M57,58 L73,58 L73,70 C73,76 65,80 65,80 C65,80 57,76 57,70 Z"
        fill="none"
        stroke="#ffffff"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M65,74 L65,63 M61,67 L65,63 L69,67"
        fill="none"
        stroke="#ffffff"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// --- Shared form controls, styled to match (teal accent, dark-mode aware)
// instead of each page hand-rolling its own blue-600/gray Tailwind classes.

export function AuthButton({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={`rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400 ${className}`}
    />
  );
}

export function AuthSecondaryButton({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={`rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800 ${className}`}
    />
  );
}

export function AuthField({
  label,
  id,
  value,
  onChange,
  type = "text",
  placeholder,
  required,
}: {
  label: string;
  id: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
        {label}
      </label>
      <input
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100 dark:placeholder:text-gray-500"
      />
    </div>
  );
}
