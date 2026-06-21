import { useEffect, useState } from "react";
import { getHealth } from "../lib/api";

const PROJECT_URL = "https://modulab.app";
const GITHUB_URL = "https://github.com/modulab-project/modulab-core";

// Reads the running backend's version from /healthz on mount rather than
// hardcoding it here - the frontend and backend are built independently and
// can drift, so this always shows what's actually running, not what was
// true when this file was last edited. Failure is silent (just omits the
// version) since a footer is not worth showing an error state for.
export default function Footer() {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    getHealth()
      .then((health) => setVersion(health.version))
      .catch(() => setVersion(null));
  }, []);

  const year = new Date().getFullYear();

  return (
    <footer className="mx-auto max-w-xl px-4 py-6 text-center text-xs text-gray-400">
      <p>
        © {year} ModuLab{version ? ` · ${version}` : ""} ·{" "}
        <a href={PROJECT_URL} className="hover:text-gray-600">
          modulab.app
        </a>{" "}
        ·{" "}
        <a href={GITHUB_URL} className="hover:text-gray-600">
          GitHub
        </a>
      </p>
    </footer>
  );
}
