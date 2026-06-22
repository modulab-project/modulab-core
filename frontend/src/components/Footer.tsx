const PROJECT_URL = "https://modulab.app";
const GITHUB_URL = "https://github.com/modulab-project/modulab-core";

// No longer shows the running backend version (dropped 2026-06-21 on user
// request) - it used to fetch /healthz just for this, which also meant a
// network round trip on every auth-flow page just to render a footer.
// version.go / the /healthz field themselves are untouched - the system
// status panel on the real Home.tsx page is still the place to check the
// running version.
export default function Footer() {
  const year = new Date().getFullYear();

  return (
    <footer className="mx-auto max-w-xl px-4 py-6 text-center text-xs text-gray-400 dark:text-gray-500">
      <p>
        © {year} ModuLab ·{" "}
        <a href={PROJECT_URL} className="hover:text-gray-600 dark:hover:text-gray-300">
          modulab.app
        </a>{" "}
        ·{" "}
        <a href={GITHUB_URL} className="hover:text-gray-600 dark:hover:text-gray-300">
          GitHub
        </a>
      </p>
    </footer>
  );
}
