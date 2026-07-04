// Tailwind v4: CSS processing now happens via the @tailwindcss/vite plugin
// (see vite.config.ts), not via PostCSS. This file is intentionally left
// with no plugins - autoprefixer is no longer needed either, v4 handles
// vendor prefixing internally. Kept only so a stray PostCSS config file
// doesn't silently reference the removed v3 "tailwindcss"/"autoprefixer"
// packages if something still picks this file up.
export default {
  plugins: {},
};
