/** Highlight vulnerable lines in red within surrounding context. */
export function CodeHighlight({ code, startLine, endLine, pad = 10, className = "" }) {
  if (!code) {
    return <p className="text-sm text-muted py-3">Không có nguồn code để tô sáng.</p>;
  }
  const lines = code.replace(/\r\n/g, "\n").split("\n");
  const s = Math.max(0, (startLine || 1) - 1 - pad);
  const e = Math.min(lines.length, (endLine || startLine || 1) + pad);
  const view = [];
  for (let i = s; i < e; i += 1) {
    const ln = i + 1;
    const hot = ln >= startLine && ln <= (endLine || startLine);
    view.push(
      <div key={ln} className={hot ? "code-line hot" : "code-line"}>
        <span className="ln">{ln}</span>
        <span className="lt">{lines[i] === "" ? " " : lines[i]}</span>
      </div>
    );
  }
  return <div className={`code-view ${className}`.trim()}>{view}</div>;
}
