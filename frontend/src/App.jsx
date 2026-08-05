import { useCallback, useEffect, useState } from "react";
import { fetchHealth } from "./api";
import { SiteNav } from "./components/SiteNav.jsx";
import Home from "./pages/Home.jsx";
import Workspace from "./pages/Workspace.jsx";

function usePath() {
  const [path, setPath] = useState(() => window.location.pathname || "/");
  const [boot, setBoot] = useState(null);

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname || "/");
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = useCallback((to, opts = {}) => {
    const target = to === "/app" || to.startsWith("/app") ? "/app" : "/";
    window.history.pushState({}, "", target);
    setPath(target);
    setBoot(opts.sample || null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  return { path, navigate, boot };
}

export default function App() {
  const { path, navigate, boot } = usePath();
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  return (
    <div className="shell">
      <SiteNav path={path} navigate={navigate} health={health} />
      {path.startsWith("/app") ? <Workspace bootSample={boot} /> : <Home navigate={navigate} />}
    </div>
  );
}
