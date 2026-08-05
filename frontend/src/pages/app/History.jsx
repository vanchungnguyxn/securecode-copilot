import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Search, Trash2 } from "lucide-react";
import { api } from "../../lib/api";
import { formatDate } from "../../lib/utils";
import { Button } from "../../components/ui/Button";
import { Select } from "../../components/ui/Input";
import { Card } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Skeleton } from "../../components/ui/Skeleton";
import { useToast } from "../../components/ui/Toast";

const PAGE_SIZE = 10;

export default function History() {
  const { toast } = useToast();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [lang, setLang] = useState("");
  const [page, setPage] = useState(0);

  async function load() {
    setLoading(true);
    try {
      const data = await api.listAnalyses({ limit: 100 });
      setItems(data);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return items.filter((a) => {
      if (lang && a.language !== lang) return false;
      if (!qq) return true;
      return (
        (a.filename || "").toLowerCase().includes(qq) ||
        (a.project_name || "").toLowerCase().includes(qq)
      );
    });
  }, [items, q, lang]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const slice = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);

  useEffect(() => {
    setPage(0);
  }, [q, lang]);

  async function onDelete(id, e) {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm("Xóa phân tích này?")) return;
    await api.deleteAnalysis(id);
    toast("Đã xóa");
    load();
  }

  return (
    <div>
      <Helmet>
        <title>Lịch sử · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-2xl font-semibold tracking-tight">Lịch sử phân tích</h1>
      <p className="text-sm text-muted mt-1">Tìm và lọc trên dữ liệu đã tải</p>

      <div className="mt-4 flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
          <input
            className="w-full h-10 rounded-lg border border-border bg-surface pl-9 pr-3 text-sm"
            placeholder="Tìm project / file…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <Select className="w-40 !space-y-0" value={lang} onChange={(e) => setLang(e.target.value)}>
          <option value="">Tất cả ngôn ngữ</option>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="java">Java</option>
          <option value="c">C</option>
          <option value="cpp">C++</option>
        </Select>
      </div>

      <Card className="mt-4 overflow-hidden">
        {loading ? (
          <div className="p-4 space-y-2">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : slice.length === 0 ? (
          <p className="p-10 text-center text-sm text-muted">Không có phân tích nào.</p>
        ) : (
          <ul className="divide-y divide-border">
            {slice.map((a) => (
              <li key={a.id}>
                <Link
                  to={`/dashboard/history/${a.id}`}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-bg text-sm"
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{a.project_name}</p>
                    <p className="text-xs text-muted font-mono truncate">
                      {a.filename} · {a.language} · {formatDate(a.created_at)}
                    </p>
                  </div>
                  <span className="text-muted shrink-0">{a.vulnerability_count} issues</span>
                  {a.highest_severity ? <Badge>{a.highest_severity}</Badge> : <Badge variant="success">clean</Badge>}
                  <Button size="icon" variant="ghost" onClick={(e) => onDelete(a.id, e)} aria-label="Xóa">
                    <Trash2 className="h-4 w-4 text-muted" />
                  </Button>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {pageCount > 1 ? (
        <div className="mt-4 flex items-center justify-center gap-2">
          <Button size="sm" variant="secondary" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            Trước
          </Button>
          <span className="text-sm text-muted">
            {page + 1}/{pageCount}
          </span>
          <Button
            size="sm"
            variant="secondary"
            disabled={page >= pageCount - 1}
            onClick={() => setPage((p) => p + 1)}
          >
            Sau
          </Button>
        </div>
      ) : null}
    </div>
  );
}
