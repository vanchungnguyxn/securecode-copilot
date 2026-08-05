import { useEffect, useState } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { ArrowLeft, Trash2 } from "lucide-react";
import { api } from "../../lib/api";
import { formatDate, severityColor, cn } from "../../lib/utils";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { PageSkeleton } from "../../components/ui/Skeleton";
import { CodeHighlight } from "../../components/CodeHighlight";
import { useToast } from "../../components/ui/Toast";

export default function HistoryDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState(null);

  useEffect(() => {
    setLoading(true);
    api
      .getAnalysis(id)
      .then((d) => {
        setData(d);
        setSelectedId(d.result?.vulnerabilities?.[0]?.id || null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  async function onDelete() {
    if (!confirm("Xóa phân tích này?")) return;
    await api.deleteAnalysis(id);
    toast("Đã xóa");
    navigate("/dashboard/history");
  }

  if (loading) return <PageSkeleton />;
  if (error || !data) {
    return (
      <div>
        <p className="text-danger">{error || "Không tìm thấy"}</p>
        <Link to="/dashboard/history" className="text-primary text-sm mt-2 inline-block">
          ← Lịch sử
        </Link>
      </div>
    );
  }

  const vulns = data.result?.vulnerabilities || [];
  const selected = vulns.find((v) => v.id === selectedId) || vulns[0] || null;

  return (
    <div>
      <Helmet>
        <title>{data.project_name} · Lịch sử</title>
      </Helmet>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link to="/dashboard/history" className="text-sm text-muted hover:text-fg inline-flex items-center gap-1">
            <ArrowLeft className="h-4 w-4" /> Lịch sử
          </Link>
          <h1 className="text-2xl font-semibold mt-2 tracking-tight">{data.project_name}</h1>
          <p className="text-sm text-muted font-mono mt-1">
            {data.filename} · {data.language} · {formatDate(data.created_at)} · {data.line_count} dòng
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant={data.status === "completed" ? "success" : "default"}>{data.status}</Badge>
          <Button size="sm" variant="danger" onClick={onDelete}>
            <Trash2 className="h-3.5 w-3.5" /> Xóa
          </Button>
        </div>
      </div>

      <div className="mt-4 flex gap-3 text-sm">
        <Card className="px-4 py-3">
          <span className="text-muted">Findings: </span>
          <strong>{data.vulnerability_count}</strong>
        </Card>
        {data.highest_severity ? (
          <Card className="px-4 py-3">
            <span className="text-muted">Highest: </span>
            <strong className="capitalize">{data.highest_severity}</strong>
          </Card>
        ) : null}
      </div>

      <div className="mt-4 grid lg:grid-cols-[1fr_1.1fr] gap-4">
        <Card className="overflow-hidden">
          <div className="px-4 py-3 border-b border-border font-medium text-sm">Vulnerabilities</div>
          {vulns.length === 0 ? (
            <p className="p-6 text-sm text-muted text-center">Không có finding</p>
          ) : (
            <ul className="divide-y divide-border max-h-[420px] overflow-y-auto">
              {vulns.map((v) => (
                <li key={v.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(v.id)}
                    className={cn(
                      "w-full text-left px-4 py-3 text-sm transition-colors",
                      selected?.id === v.id ? "bg-primary/5" : "hover:bg-fg/[0.03]"
                    )}
                  >
                    <div className="flex justify-between gap-2">
                      <span className="font-medium">{v.title}</span>
                      <span className={cn("rounded border px-1.5 text-[10px] uppercase h-fit", severityColor(v.severity))}>
                        {v.severity}
                      </span>
                    </div>
                    <p className="text-xs text-muted font-mono mt-1">
                      {v.cwe} · L{v.start_line}–{v.end_line}
                    </p>
                    <p className="text-muted mt-1 line-clamp-2">{v.message}</p>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="overflow-hidden p-4">
          <h2 className="text-sm font-medium mb-3">
            {selected ? "Đoạn code lỗi (tô đỏ)" : "Source"}
          </h2>
          {selected && data.source_code ? (
            <CodeHighlight
              code={data.source_code}
              startLine={selected.start_line}
              endLine={selected.end_line}
              pad={14}
            />
          ) : data.source_code ? (
            <pre className="p-4 text-xs font-mono overflow-x-auto max-h-80 bg-[#0d1117] text-slate-200 rounded-lg border border-border">
              {data.source_code}
            </pre>
          ) : (
            <p className="text-sm text-muted">Không có source</p>
          )}
        </Card>
      </div>
    </div>
  );
}
