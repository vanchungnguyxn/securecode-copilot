import { useEffect, useMemo, useState } from "react";
import {
  applyFix,
  explainFinding,
  fetchHealth,
  fixFinding,
  scanCode,
  scanRepo,
  scanRepoZip,
  SAMPLES,
} from "../api";
import { CodeHighlight } from "../components/CodeHighlight.jsx";

function countSeverity(result) {
  const c = result?.severity_counts || {};
  return {
    critical: c.critical || 0,
    high: c.high || 0,
    medium: c.medium || 0,
    total: result?.vulnerability_count || 0,
  };
}

function flattenRepo(repo) {
  const vulnerabilities = [];
  const explanations = [];
  const fixes = [];
  const files = {};
  for (const r of repo.results || []) {
    if (r.filename && r.source_code != null) {
      files[r.filename] = { code: r.source_code, language: r.language || "auto" };
    }
    for (const v of r.vulnerabilities || []) vulnerabilities.push(v);
    for (const e of r.explanations || []) explanations.push(e);
    for (const f of r.fixes || []) fixes.push(f);
  }
  return {
    scan_id: repo.scan_id,
    language: "multi",
    filename: repo.source,
    vulnerability_count: repo.vulnerability_count,
    severity_counts: repo.severity_counts || {},
    vulnerabilities,
    explanations,
    fixes,
    files,
    meta: { ...repo.meta, file_count: repo.file_count, scanned_files: repo.scanned_files, mode: "repo" },
  };
}

const EXT = {
  python: "py",
  javascript: "js",
  java: "java",
  c: "c",
  cpp: "cpp",
};

export default function Workspace({ bootSample }) {
  const [language, setLanguage] = useState(bootSample && SAMPLES[bootSample] ? bootSample : "python");
  const [code, setCode] = useState(
    bootSample && SAMPLES[bootSample] ? SAMPLES[bootSample] : SAMPLES.python
  );
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [health, setHealth] = useState(null);
  const [toast, setToast] = useState("");
  const [enriching, setEnriching] = useState(false);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 2200);
    return () => clearTimeout(t);
  }, [toast]);

  const selected = useMemo(() => {
    if (!result) return null;
    return result.vulnerabilities.find((v) => v.id === selectedId) || result.vulnerabilities[0] || null;
  }, [result, selectedId]);

  const explanation = useMemo(() => {
    if (!result || !selected) return null;
    return (result.explanations || []).find((e) => e.vulnerability_id === selected.id) || null;
  }, [result, selected]);

  const fix = useMemo(() => {
    if (!result || !selected) return null;
    return (result.fixes || []).find((f) => f.vulnerability_id === selected.id) || null;
  }, [result, selected]);

  // Lazy CodeT5/heuristic enrich when user picks a finding (keeps Scan fast)
  useEffect(() => {
    if (!result || !selected) return;
    const hasExpl = (result.explanations || []).some((e) => e.vulnerability_id === selected.id);
    const hasFix = (result.fixes || []).some((f) => f.vulnerability_id === selected.id);
    if (hasExpl && hasFix) return;

    let cancelled = false;
    (async () => {
      setEnriching(true);
      try {
        const src =
          (selected.file && result.files?.[selected.file]?.code) ||
          result.source_code ||
          code;
        const payload = { code: src, vulnerability: selected };
        const [ex, fx] = await Promise.all([
          hasExpl ? null : explainFinding(payload),
          hasFix ? null : fixFinding(payload),
        ]);
        if (cancelled) return;
        setResult((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            explanations: ex
              ? [...(prev.explanations || []).filter((e) => e.vulnerability_id !== selected.id), ex]
              : prev.explanations || [],
            fixes: fx
              ? [...(prev.fixes || []).filter((f) => f.vulnerability_id !== selected.id), fx]
              : prev.fixes || [],
          };
        });
      } catch (e) {
        if (!cancelled) setError(e.message || "Explain/fix failed");
      } finally {
        if (!cancelled) setEnriching(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedId, selected?.id, result?.scan_id]);

  const metrics = countSeverity(result);

  async function onScan() {
    setLoading(true);
    setError("");
    try {
      // Findings first — explain/fix load on select (avoids long timeout / empty UI)
      const data = await scanCode({
        code,
        language,
        filename: `demo.${EXT[language] || "txt"}`,
        include_explanations: false,
        include_fixes: false,
      });
      const fname = data.filename || `demo.${EXT[language] || "txt"}`;
      setResult({
        ...data,
        explanations: data.explanations || [],
        fixes: data.fixes || [],
        files: { [fname]: { code, language } },
        vulnerabilities: (data.vulnerabilities || []).map((v) => ({ ...v, file: v.file || fname })),
      });
      setSelectedId(data.vulnerabilities[0]?.id || null);
      setToast(`${data.vulnerability_count} findings · explain/fix khi chọn issue`);
    } catch (e) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  async function onScanRepo() {
    if (!repoUrl.trim()) {
      setError("Nhập GitHub URL (https://github.com/owner/repo)");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const repo = await scanRepo({
        github_url: repoUrl.trim(),
        include_explanations: false,
        include_fixes: false,
        max_files: 300,
        max_enrich: 0,
        ml_discovery: false,
      });
      const flat = flattenRepo(repo);
      setResult(flat);
      const first = flat.vulnerabilities[0];
      setSelectedId(first?.id || null);
      if (first?.file && flat.files?.[first.file]) {
        setCode(flat.files[first.file].code);
        setLanguage(flat.files[first.file].language || "auto");
      }
      setToast(
        `Repo: ${repo.scanned_files} files · ${repo.vulnerability_count} findings · explain/fix khi chọn`
      );
    } catch (e) {
      setError(e.message || "Repo scan failed");
    } finally {
      setLoading(false);
    }
  }

  async function onZip(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError("");
    try {
      const repo = await scanRepoZip(file, {
        max_files: 300,
        max_enrich: 0,
        include_explanations: false,
        include_fixes: false,
        ml_discovery: false,
      });
      const flat = flattenRepo(repo);
      setResult(flat);
      const first = flat.vulnerabilities[0];
      setSelectedId(first?.id || null);
      if (first?.file && flat.files?.[first.file]) {
        setCode(flat.files[first.file].code);
        setLanguage(flat.files[first.file].language || "auto");
      }
      setToast(
        `Zip: ${repo.scanned_files} files · ${repo.vulnerability_count} findings · explain/fix khi chọn`
      );
    } catch (err) {
      setError(err.message || "Zip scan failed");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  }

  function loadSample(lang) {
    setLanguage(lang);
    setCode(SAMPLES[lang] || "");
    setResult(null);
    setSelectedId(null);
  }

  function onSelectFinding(id) {
    setSelectedId(id);
    const v = result?.vulnerabilities?.find((x) => x.id === id);
    if (v?.file && result?.files?.[v.file]) {
      setCode(result.files[v.file].code);
      setLanguage(result.files[v.file].language || "auto");
    }
  }

  const activeCode = useMemo(() => {
    if (selected?.file && result?.files?.[selected.file]?.code) {
      return result.files[selected.file].code;
    }
    return code;
  }, [selected, result, code]);

  async function onApplyFix() {
    if (!selected || !fix) return;
    try {
      const res = await applyFix({
        code: activeCode,
        fixed_snippet: fix.fixed_code,
        start_line: selected.start_line,
        end_line: selected.end_line,
      });
      setCode(res.code);
      if (selected.file && result?.files) {
        setResult({
          ...result,
          files: {
            ...result.files,
            [selected.file]: { ...result.files[selected.file], code: res.code },
          },
        });
      }
      setToast("Đã áp dụng bản vá vào editor");
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="workspace">
      <div className="ws-glow" aria-hidden />

      <header className="ws-head">
        <div>
          <div className="section-kicker">Studio</div>
          <h1 className="ws-title">Workspace</h1>
          <p className="ws-sub">
            Quét file hoặc repo · hybrid detect · explain &amp; fix
            {health ? ` · ${health.llm_provider}` : ""}
          </p>
        </div>
        <div className={`ws-status ${health ? "on" : ""}`}>
          <span className="ws-dot" />
          {health ? "API connected" : "API offline"}
        </div>
      </header>

      <div className="ws-ingest">
        <div className="ws-ingest-label">Repo</div>
        <input
          className="field"
          placeholder="https://github.com/owner/repo"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
        />
        <button className="btn btn-primary" type="button" onClick={onScanRepo} disabled={loading}>
          {loading ? "Đang quét…" : "Scan repo"}
        </button>
        <label className="btn btn-ghost file-btn">
          Upload ZIP
          <input type="file" accept=".zip" hidden onChange={onZip} />
        </label>
      </div>

      <div className="ws-grid">
        <section className="ws-editor" aria-label="Editor">
          <div className="ws-chrome">
            <div className="ws-chrome-dots" aria-hidden>
              <i />
              <i />
              <i />
            </div>
            <span className="ws-chrome-title">editor · {language}</span>
          </div>
          <div className="ws-toolbar">
            <select className="field select" value={language} onChange={(e) => setLanguage(e.target.value)} aria-label="Language">
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="java">Java</option>
              <option value="c">C</option>
              <option value="cpp">C++</option>
              <option value="auto">Auto-detect</option>
            </select>
            <div className="sample-row">
              {["python", "javascript", "java", "c"].map((l) => (
                <button key={l} className="btn btn-quiet" type="button" onClick={() => loadSample(l)}>
                  {l === "javascript" ? "JS" : l === "python" ? "Py" : l === "java" ? "Java" : "C"}
                </button>
              ))}
            </div>
            <button className="btn btn-lime" type="button" onClick={onScan} disabled={loading || !code.trim()}>
              {loading ? "Đang quét…" : "Scan + Explain + Fix"}
            </button>
          </div>
          <textarea
            className="code-area"
            spellCheck={false}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Dán source code cần phân tích…"
          />
          {error ? <p className="error">{error}</p> : null}
        </section>

        <aside className="ws-side" aria-label="Findings">
          <div className="ws-side-head">
            <h2>Overview</h2>
          </div>
          <div className="metrics">
            <div className="metric">
              <strong>{metrics.total}</strong>
              <span>Total</span>
            </div>
            <div className="metric crit">
              <strong>{metrics.critical}</strong>
              <span>Critical</span>
            </div>
            <div className="metric high">
              <strong>{metrics.high}</strong>
              <span>High</span>
            </div>
            <div className="metric med">
              <strong>{metrics.medium}</strong>
              <span>Medium</span>
            </div>
          </div>

          <div className="findings">
            <div className="findings-head">
              <h2>Findings</h2>
              {result?.meta?.scanned_files != null ? (
                <span className="findings-count">
                  {result.meta.scanned_files}/{result.meta.file_count || "?"} files
                </span>
              ) : null}
            </div>
            {!result ? (
              <div className="empty-state">
                <div className="empty-art" aria-hidden />
                <p className="empty">Chọn sample hoặc dán code, rồi Scan. Repo / ZIP cho cả project.</p>
              </div>
            ) : result.vulnerabilities.length === 0 ? (
              <div className="empty-state ok">
                <p className="empty">Không tìm thấy lỗ hổng trên lần quét này.</p>
              </div>
            ) : (
              <div className="findings-list">
                {result.vulnerabilities.map((v, i) => (
                  <button
                    type="button"
                    key={v.id}
                    className={selected?.id === v.id ? "finding active" : "finding"}
                    style={{ animationDelay: `${i * 35}ms` }}
                    onClick={() => onSelectFinding(v.id)}
                  >
                    <span className="finding-top">
                      <span className="finding-title">{v.title}</span>
                      <span className={`sev ${v.severity}`}>{v.severity}</span>
                    </span>
                    <span className="finding-meta">
                      {v.file ? `${v.file} · ` : ""}
                      {v.cwe} · L{v.start_line} · {v.detector}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </aside>
      </div>

      {selected && (
        <section className="ws-detail" aria-label="Chi tiết">
          <div className="ws-detail-banner">
            <h2>
              {selected.title}
              <span className={`sev ${selected.severity}`}>{selected.severity}</span>
            </h2>
            <p className="ws-detail-path">
              {selected.file ? `${selected.file} · ` : ""}dòng {selected.start_line}
              {selected.end_line !== selected.start_line ? `–${selected.end_line}` : ""}
            </p>
          </div>
          <div className="detail-grid">
            <div className="detail-col">
              <h3>Đoạn code lỗi (tô đỏ)</h3>
              <CodeHighlight
                code={activeCode}
                startLine={selected.start_line}
                endLine={selected.end_line}
                pad={12}
              />
              <p className="muted">{selected.message}</p>
              <p className="finding-meta">
                {selected.owasp} · confidence {(selected.confidence * 100).toFixed(0)}% · {selected.detector}
              </p>
            </div>
            <div className="detail-col">
              <h3>Giải thích</h3>
              {explanation ? (
                <>
                  <p>
                    <strong>{explanation.summary}</strong>
                  </p>
                  {selected?.snippet ? (
                    <pre className="code-block explain-snip">{selected.snippet}</pre>
                  ) : null}
                  <p className="body-gap explain-prose">{explanation.why_vulnerable}</p>
                  <p className="body-gap explain-prose">{explanation.impact}</p>
                  <h3 className="body-gap">Kịch bản tấn</h3>
                  <pre className="code-block">{explanation.attack_scenario}</pre>
                  {explanation.secure_coding_tips?.length ? (
                    <>
                      <h3 className="body-gap">Gợi ý an toàn</h3>
                      <ul className="tip-list">
                        {explanation.secure_coding_tips.map((t) => (
                          <li key={t}>{t}</li>
                        ))}
                      </ul>
                    </>
                  ) : null}
                </>
              ) : (
                <p className="empty">
                  {enriching ? "Đang sinh giải thích…" : "Chọn finding — hệ thống sẽ tự giải thích."}
                </p>
              )}
            </div>
          </div>
          {fix ? (
            <div className="fix-block">
              <div className="fix-head">
                <h3>Hướng fix đề xuất · {fix.strategy}</h3>
                <button className="btn btn-lime" type="button" onClick={onApplyFix}>
                  Apply fix vào editor
                </button>
              </div>
              <p className="muted" style={{ marginBottom: "0.55rem" }}>
                {fix.description}
              </p>
              <pre className="code-block">{fix.fixed_code}</pre>
            </div>
          ) : (
            <div className="fix-block">
              <h3>Hướng fix</h3>
              <p className="empty">{enriching ? "Đang đề xuất bản vá…" : "Chưa có bản vá — đang chờ enrich."}</p>
            </div>
          )}
        </section>
      )}

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  );
}
