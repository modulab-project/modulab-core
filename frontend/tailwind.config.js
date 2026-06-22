/** @type {import('tailwindcss').Config} */
export default {
  // Manual toggle (Home.tsx flips the "dark" class on <html>), not OS
  // preference - the start page has its own dark/light switch in the
  // profile panel, which would conflict with Tailwind's default
  // media-query-based dark mode.
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {},
  },
  plugins: [],
};
