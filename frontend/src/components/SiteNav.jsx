export function SiteNav({ path, navigate, health }) {
  return (
    <nav className="nav" aria-label="Chính">
      <button type="button" className="nav-brand" onClick={() => navigate("/")}>
        <span className="nav-mark" aria-hidden />
        <span className="nav-name">SecureCode Copilot</span>
      </button>
      <div className="nav-links">
        <button type="button" className={path === "/" ? "nav-link active" : "nav-link"} onClick={() => navigate("/")}>
          Trang chủ
        </button>
        <button
          type="button"
          className={path.startsWith("/app") ? "nav-link active" : "nav-link"}
          onClick={() => navigate("/app")}
        >
          Workspace
        </button>
        <span className={health ? "nav-health on" : "nav-health"}>{health ? `API · ${health.llm_provider}` : "API offline"}</span>
      </div>
    </nav>
  );
}
