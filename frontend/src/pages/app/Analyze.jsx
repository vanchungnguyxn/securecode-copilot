import { useEffect, useMemo, useState, useRef, lazy, Suspense } from "react";
import { Helmet } from "react-helmet-async";
import { Link } from "react-router-dom";
import { Copy, Download, Play, AlertCircle, Github, Upload } from "lucide-react";
import { api, ApiError, SAMPLES, LANG_EXT } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { useToast } from "../../components/ui/Toast";
import { Button } from "../../components/ui/Button";
import { Select } from "../../components/ui/Input";
import { Card } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { QuotaBar } from "../../components/ui/QuotaBar";
import { CodeHighlight } from "../../components/CodeHighlight";
import { cn, severityColor } from "../../lib/utils";

const Monaco = lazy(() => import("@monaco-editor/react"));

const STEPS = ["Chuẩn bị", "Quét", "Findings", "Explain/Fix"];

function flattenRepo(repo) {
  const vulnerabilities = [];
  const explanations = [];
  const fixes = [];
  const files = {};
  for (const r of repo.results || []) {
    if (r.filename && r.source_code != null) {
      files[r.filename] = { code: r.source_code, language: r.language || "auto" };
    }
    for (const v of r.vulnerabilities || []) {
      vulnerabilities.push({ ...v, file: v.file || r.filename });
    }
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
    source_code: null,
    meta: {
      ...repo.meta,
      file_count: repo.file_count,
      scanned_files: repo.scanned_files,
      mode: "repo",
    },
  };
}

export default function Analyze() {
  const { user, refresh } = useAuth();
  const { toast } = useToast();
  const [language, setLanguage] = useState("python");
  const [code, setCode] = useState(SAMPLES.python);
  const [projectName, setProjectName] = useState("Untitled");
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [quotaMsg, setQuotaMsg] = useState("");
  const [analysisId, setAnalysisId] = useState(null);
  const [result, setResult] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [enriching, setEnriching] = useState(false);
  const editorRef = useRef(null);
  const decoRef = useRef([]);

  const selected = useMemo(() => {
    if (!result) return null;
    return result.vulnerabilities?.find((v) => v.id === selectedId) || result.vulnerabilities?.[0] || null;
  }, [result, selectedId]);

  const activeCode = useMemo(() => {
    if (selected?.file && result?.files?.[selected.file]?.code) {
      return result.files[selected.file].code;
    }
    return result?.source_code || code;
  }, [selected, result, code]);

  // Tô đỏ dòng lỗ hổng trên Monaco khi chọn finding
  function applyVulnDecorations(editor) {
    if (!editor) return;
    if (!selected?.start_line) {
      decoRef.current = editor.deltaDecorations(decoRef.current, []);
      return;
    }
    const start = Math.max(1, selected.start_line);
    const end = Math.max(start, selected.end_line || start);
    decoRef.current = editor.deltaDecorations(decoRef.current, [
      {
        range: {
          startLineNumber: start,
          startColumn: 1,
          endLineNumber: end,
          endColumn: Number.MAX_SAFE_INTEGER,
        },
        options: {
          isWholeLine: true,
          className: "monaco-vuln-line",
          linesDecorationsClassName: "monaco-vuln-glyph",
          overviewRuler: {
            color: "#f85149",
            position: 1,
          },
        },
      },
    ]);
    editor.revealLineInCenter(start);
  }

  useEffect(() => {
    applyVulnDecorations(editorRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id, selected?.start_line, selected?.end_line, code]);

  const explanation = useMemo(() => {
    if (!result || !selected) return null;
    return (result.explanations || []).find((e) => e.vulnerability_id === selected.id) || null;
  }, [result, selected]);

  const fix = useMemo(() => {
    if (!result || !selected) return null;
    return (result.fixes || []).find((f) => f.vulnerability_id === selected.id) || null;
  }, [result, selected]);

  useEffect(() => {
    if (!result || !selected) return;
    const hasExpl = (result.explanations || []).some((e) => e.vulnerability_id === selected.id);
    const hasFix = (result.fixes || []).some((f) => f.vulnerability_id === selected.id);
    if (hasExpl && hasFix) return;

    let cancelled = false;
    (async () => {
      setEnriching(true);
      setStep(3);
      try {
        const src =
          (selected.file && result.files?.[selected.file]?.code) ||
          result.source_code ||
          code;
        const payload = { code: src, vulnerability: selected };
        const [ex, fx] = await Promise.all([
          hasExpl ? null : api.explain(payload),
          hasFix ? null : api.fix(payload),
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
        if (!cancelled) toast(e.message || "Explain/Fix lỗi", { variant: "danger" });
      } finally {
        if (!cancelled) setEnriching(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, selected?.id, analysisId, result?.scan_id]);

  function loadSample(lang) {
    setLanguage(lang);
    setCode(SAMPLES[lang] || "");
    setResult(null);
    setSelectedId(null);
    setAnalysisId(null);
    setStep(0);
    setError("");
    setQuotaMsg("");
  }

  function onSelectFinding(id) {
    setSelectedId(id);
    const v = result?.vulnerabilities?.find((x) => x.id === id);
    if (v?.file && result?.files?.[v.file]) {
      setCode(result.files[v.file].code);
      setLanguage(result.files[v.file].language || "auto");
    }
  }

  async function onScan() {
    setLoading(true);
    setError("");
    setQuotaMsg("");
    setStep(1);
    try {
      const data = await api.createAnalysis({
        code,
        language,
        filename: `scan.${LANG_EXT[language] || "txt"}`,
        project_name: projectName || "Untitled",
        include_explanations: false,
        include_fixes: false,
      });
      setStep(2);
      setAnalysisId(data.id);
      const payload = data.result || {};
      const fname = data.filename || `scan.${LANG_EXT[language] || "txt"}`;
      setResult({
        ...payload,
        source_code: data.source_code || code,
        explanations: payload.explanations || [],
        fixes: payload.fixes || [],
        vulnerabilities: (payload.vulnerabilities || []).map((v) => ({
          ...v,
          file: v.file || fname,
        })),
        files: { [fname]: { code: data.source_code || code, language } },
      });
      setSelectedId(payload.vulnerabilities?.[0]?.id || null);
      await refresh();
      toast(`Tìm thấy ${data.vulnerability_count} findings`, { variant: "success" });
    } catch (e) {
      if (e instanceof ApiError && (e.code === "QUOTA_EXCEEDED" || e.status === 402)) {
        setQuotaMsg(e.message);
        setError("");
      } else {
        setError(e.message || "Quét thất bại");
      }
      setStep(0);
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
    setQuotaMsg("");
    setAnalysisId(null);
    setStep(1);
    try {
      const repo = await api.scanRepo({
        github_url: repoUrl.trim(),
        include_explanations: false,
        include_fixes: false,
        max_files: 300,
        max_enrich: 0,
        ml_discovery: false,
      });
      const flat = flattenRepo(repo);
      setStep(2);
      setResult(flat);
      setProjectName(repo.source || projectName);
      const first = flat.vulnerabilities[0];
      setSelectedId(first?.id || null);
      if (first?.file && flat.files?.[first.file]) {
        setCode(flat.files[first.file].code);
        setLanguage(flat.files[first.file].language || "auto");
      }
      toast(
        `Repo: ${repo.scanned_files} files · ${repo.vulnerability_count} findings · explain/fix khi chọn`,
        { variant: "success" }
      );
    } catch (e) {
      setError(e.message || "Repo scan thất bại");
      setStep(0);
    } finally {
      setLoading(false);
    }
  }

  async function onZip(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError("");
    setQuotaMsg("");
    setAnalysisId(null);
    setStep(1);
    try {
      const repo = await api.scanRepoZip(file, {
        max_files: 300,
        max_enrich: 0,
        include_explanations: false,
        include_fixes: false,
        ml_discovery: false,
      });
      const flat = flattenRepo(repo);
      setStep(2);
      setResult(flat);
      setProjectName(file.name.replace(/\.zip$/i, "") || projectName);
      const first = flat.vulnerabilities[0];
      setSelectedId(first?.id || null);
      if (first?.file && flat.files?.[first.file]) {
        setCode(flat.files[first.file].code);
        setLanguage(flat.files[first.file].language || "auto");
      }
      toast(
        `Zip: ${repo.scanned_files} files · ${repo.vulnerability_count} findings · explain/fix khi chọn`,
        { variant: "success" }
      );
    } catch (err) {
      setError(err.message || "Zip scan thất bại");
      setStep(0);
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  }

  async function onApplyFix() {
    if (!selected || !fix) return;
    try {
      const res = await api.applyFix({
        code: activeCode,
        fixed_snippet: fix.fixed_code,
        start_line: selected.start_line,
        end_line: selected.end_line,
      });
      setCode(res.code);
      setResult((prev) => {
        if (!prev) return prev;
        const next = { ...prev, source_code: prev.source_code ? res.code : prev.source_code };
        if (selected.file && prev.files?.[selected.file]) {
          next.files = {
            ...prev.files,
            [selected.file]: { ...prev.files[selected.file], code: res.code },
          };
        }
        return next;
      });
      toast("Đã áp dụng bản vá vào editor", { variant: "success" });
    } catch (e) {
      toast(e.message, { variant: "danger" });
    }
  }

  function copyFix() {
    if (!fix?.fixed_code) return;
    navigator.clipboard.writeText(fix.fixed_code);
    toast("Đã copy snippet");
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify({ analysis_id: analysisId, ...result }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `analysis-${analysisId || result?.scan_id || "export"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const counts = result?.severity_counts || {};
  const isRepoMode = result?.meta?.mode === "repo";

  return (
    <div>
      <Helmet>
        <title>Phân tích · SecureCode Copilot</title>
      </Helmet>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="section-kicker">Analyze</p>
          <h1 className="mt-2 text-2xl sm:text-3xl font-semibold tracking-tight">Phân tích</h1>
          <p className="text-sm text-muted mt-1.5">
            Quét file · GitHub · ZIP · explain &amp; fix khi chọn finding
          </p>
        </div>
        <div className="w-52">
          <QuotaBar used={user?.used_this_month || 0} limit={user?.monthly_limit || 0} />
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {STEPS.map((s, i) => (
          <span
            key={s}
            className={cn(
              "rounded-md border px-2.5 py-1 text-xs",
              i <= step ? "border-primary/40 bg-primary/10 text-primary" : "border-border text-muted"
            )}
          >
            {i + 1}. {s}
          </span>
        ))}
      </div>

      {quotaMsg ? (
        <Card className="mt-4 p-4 border-danger/40 bg-danger/5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex gap-2 text-sm">
            <AlertCircle className="h-4 w-4 text-danger shrink-0 mt-0.5" />
            <span>{quotaMsg}</span>
          </div>
          <Link to="/dashboard/billing">
            <Button size="sm">Nâng cấp gói</Button>
          </Link>
        </Card>
      ) : null}

      <Card className="mt-4 p-3 flex flex-wrap items-center gap-2">
        <Github className="h-4 w-4 text-muted shrink-0" />
        <input
          className="h-9 flex-1 min-w-[220px] rounded-lg border border-border bg-surface px-3 text-sm"
          placeholder="https://github.com/owner/repo"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          disabled={loading}
        />
        <Button variant="secondary" onClick={onScanRepo} loading={loading} disabled={loading}>
          Scan repo
        </Button>
        <label className={cn("inline-flex", loading && "pointer-events-none opacity-50")}>
          <span className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-border bg-surface px-3 text-sm cursor-pointer hover:bg-bg">
            <Upload className="h-3.5 w-3.5" /> Upload ZIP
          </span>
          <input type="file" accept=".zip" className="hidden" onChange={onZip} disabled={loading} />
        </label>
      </Card>

      <div className="mt-4 grid lg:grid-cols-[1fr_320px] gap-4">
        <Card className="overflow-hidden p-0">
          <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
            <input
              className="h-9 rounded-lg border border-border bg-surface px-3 text-sm w-40"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="Tên project"
            />
            <Select
              className="w-36 !mt-0"
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              aria-label="Language"
            >
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="java">Java</option>
              <option value="c">C</option>
              <option value="cpp">C++</option>
              <option value="auto">Auto</option>
            </Select>
            <div className="flex gap-1">
              {["python", "javascript", "java", "c"].map((l) => (
                <Button key={l} size="sm" variant="ghost" onClick={() => loadSample(l)}>
                  {l === "javascript" ? "JS" : l === "python" ? "Py" : l}
                </Button>
              ))}
            </div>
            <div className="flex-1" />
            <Button onClick={onScan} loading={loading} disabled={!code.trim() || loading}>
              <Play className="h-4 w-4" /> Quét file
            </Button>
          </div>
          {isRepoMode && selected?.file ? (
            <div className="px-3 py-1.5 text-xs font-mono text-muted border-b border-border bg-bg/50 truncate">
              {selected.file}
              {result?.meta?.scanned_files != null
                ? ` · ${result.meta.scanned_files} files đã quét`
                : ""}
            </div>
          ) : null}
          <div className="monaco-wrap border-0 rounded-none h-[420px]">
            <Suspense fallback={<div className="h-full flex items-center justify-center text-muted text-sm">Đang tải editor…</div>}>
              <Monaco
                height="420px"
                language={language === "auto" ? "plaintext" : language === "c" || language === "cpp" ? "cpp" : language}
                theme="vs-dark"
                value={code}
                onChange={(v) => setCode(v || "")}
                onMount={(editor) => {
                  editorRef.current = editor;
                  applyVulnDecorations(editor);
                }}
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily: "JetBrains Mono, monospace",
                  scrollBeyondLastLine: false,
                  padding: { top: 12 },
                  glyphMargin: true,
                  lineDecorationsWidth: 8,
                  overviewRulerLanes: 2,
                }}
              />
            </Suspense>
          </div>          {error ? <p className="px-3 py-2 text-sm text-danger">{error}</p> : null}
        </Card>

        <Card className="p-4 flex flex-col max-h-[520px]">
          <div className="flex gap-3 text-center text-xs mb-3">
            <div className="flex-1 rounded-lg bg-bg border border-border p-2">
              <p className="text-lg font-semibold">{result?.vulnerability_count ?? "—"}</p>
              <p className="text-muted">Total</p>
            </div>
            <div className="flex-1 rounded-lg bg-bg border border-border p-2">
              <p className="text-lg font-semibold text-danger">{counts.critical || 0}</p>
              <p className="text-muted">Crit</p>
            </div>
            <div className="flex-1 rounded-lg bg-bg border border-border p-2">
              <p className="text-lg font-semibold text-orange-500">{counts.high || 0}</p>
              <p className="text-muted">High</p>
            </div>
          </div>
          <p className="text-sm font-medium mb-2">Findings</p>
          <div className="flex-1 overflow-y-auto space-y-1.5">
            {!result ? (
              <p className="text-sm text-muted py-8 text-center">
                Dán code, sample, GitHub URL hoặc ZIP.
              </p>
            ) : result.vulnerabilities?.length === 0 ? (
              <p className="text-sm text-success py-8 text-center">Không tìm thấy lỗ hổng.</p>
            ) : (
              result.vulnerabilities.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => onSelectFinding(v.id)}
                  className={cn(
                    "w-full text-left rounded-lg border px-3 py-2 text-sm transition",
                    selected?.id === v.id ? "border-primary bg-primary/5" : "border-border hover:bg-bg"
                  )}
                >
                  <span className="flex justify-between gap-2">
                    <span className="font-medium truncate">{v.title}</span>
                    <span className={cn("shrink-0 rounded border px-1.5 text-[10px] uppercase", severityColor(v.severity))}>
                      {v.severity}
                    </span>
                  </span>
                  <span className="block text-xs text-muted mt-0.5 font-mono truncate">
                    {v.file ? `${v.file} · ` : ""}
                    {v.cwe} · L{v.start_line}
                    {v.detector === "ml-discovery" || v.detector === "ml" ? (
                      <span className="ml-1 text-amber-600 dark:text-amber-400">· ml-discovery</span>
                    ) : null}
                  </span>
                </button>
              ))
            )}
          </div>
          {result ? (
            <Button variant="secondary" size="sm" className="mt-3 w-full" onClick={exportJson}>
              <Download className="h-3.5 w-3.5" /> Export JSON
            </Button>
          ) : null}
        </Card>
      </div>

      {selected ? (
        <Card className="mt-4 p-5 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold flex items-center gap-2">
                {selected.title}
                <Badge variant={selected.severity === "critical" || selected.severity === "high" ? "danger" : "default"}>
                  {selected.severity}
                </Badge>
              </h2>
              <p className="text-xs text-muted font-mono mt-1">
                {selected.file ? `${selected.file} · ` : ""}
                {selected.cwe}
                {selected.owasp ? ` · ${selected.owasp}` : ""}
                {` · dòng ${selected.start_line}`}
                {selected.end_line !== selected.start_line ? `–${selected.end_line}` : ""}
                {selected.detector ? ` · source=${selected.detector}` : ""}
              </p>
              {(selected.detector === "ml-discovery" || selected.detector === "ml") &&
              (selected.cwe === "CWE-Unknown" || !selected.cwe) ? (
                <p className="text-xs text-amber-700 dark:text-amber-400 mt-2">
                  CWE chưa phân loại — CodeBERT chỉ báo vùng khả nghi; chưa gán CWE/OWASP cố định.
                </p>
              ) : null}
            </div>
            <div className="flex gap-2">
              {fix ? (
                <>
                  <Button size="sm" variant="secondary" onClick={copyFix}>
                    <Copy className="h-3.5 w-3.5" /> Copy
                  </Button>
                  <Button size="sm" variant="accent" onClick={onApplyFix}>
                    Apply fix
                  </Button>
                </>
              ) : null}
            </div>
          </div>
          <p className="text-sm text-muted">{selected.message}</p>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-medium mb-2">Đoạn code lỗi (tô đỏ)</h3>
              <CodeHighlight
                code={activeCode}
                startLine={selected.start_line}
                endLine={selected.end_line}
                pad={12}
              />
              {selected.snippet ? (
                <p className="mt-2 text-xs text-muted font-mono truncate">Snippet: {selected.snippet}</p>
              ) : null}
            </div>
            <div>
              <h3 className="text-sm font-medium mb-2">Giải thích</h3>
              {explanation ? (
                <div className="text-sm space-y-2 text-muted">
                  <p className="text-fg font-medium">{explanation.summary}</p>
                  <p>{explanation.why_vulnerable}</p>
                  <p>{explanation.impact}</p>
                  {explanation.attack_scenario ? (
                    <pre className="font-mono text-xs bg-bg border border-border rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
                      {explanation.attack_scenario}
                    </pre>
                  ) : null}
                </div>
              ) : (
                <p className="text-sm text-muted">{enriching ? "Đang sinh giải thích…" : "Chưa có"}</p>
              )}
            </div>
          </div>
          <div>
            <h3 className="text-sm font-medium mb-2">Bản vá đề xuất {fix ? `· ${fix.strategy}` : ""}</h3>
            {fix ? (
              <>
                <p className="text-sm text-muted mb-2">{fix.description}</p>
                <pre className="font-mono text-xs bg-[#0d1117] text-emerald-100/90 border border-border rounded-lg p-3 overflow-x-auto">
                  {fix.fixed_code}
                </pre>
              </>
            ) : (
              <p className="text-sm text-muted">{enriching ? "Đang đề xuất bản vá…" : "Chưa có"}</p>
            )}
          </div>
        </Card>
      ) : null}
    </div>
  );
}
