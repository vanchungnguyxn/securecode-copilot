import { useEffect, useMemo, useState, lazy, Suspense } from "react";
import { Helmet } from "react-helmet-async";
import { FileDown } from "lucide-react";
import { api } from "../../lib/api";
import { Button } from "../../components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/Card";
import { Skeleton } from "../../components/ui/Skeleton";
import { useToast } from "../../components/ui/Toast";

const SeverityChart = lazy(() => import("./SeverityChart"));

export default function Reports() {
  const { toast } = useToast();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .listAnalyses({ limit: 100 })
      .then(setItems)
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, []);

  const byLang = useMemo(() => {
    const m = {};
    for (const a of items) {
      m[a.language] = (m[a.language] || 0) + 1;
    }
    return Object.entries(m).map(([name, value]) => ({ name, value }));
  }, [items]);

  const bySev = useMemo(() => {
    const map = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of items) {
      const s = (a.highest_severity || "info").toLowerCase();
      if (map[s] != null) map[s] += 1;
      else map.info += 1;
    }
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [items]);

  const totalVulns = items.reduce((s, a) => s + (a.vulnerability_count || 0), 0);

  return (
    <div>
      <Helmet>
        <title>Báo cáo · SecureCode Copilot</title>
      </Helmet>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Báo cáo</h1>
          <p className="text-sm text-muted mt-1">Tổng hợp từ lịch sử phân tích của bạn</p>
        </div>
        <Button
          variant="secondary"
          onClick={() => toast("Xuất PDF — mock (chưa implement)", { variant: "default" })}
        >
          <FileDown className="h-4 w-4" /> Xuất PDF (mock)
        </Button>
      </div>

      <div className="mt-6 grid sm:grid-cols-3 gap-4">
        <Card className="p-4">
          <p className="text-xs text-muted">Số lần quét</p>
          <p className="text-2xl font-semibold mt-1">{loading ? "…" : items.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs text-muted">Tổng findings</p>
          <p className="text-2xl font-semibold mt-1">{loading ? "…" : totalVulns}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs text-muted">TB findings / lần</p>
          <p className="text-2xl font-semibold mt-1">
            {loading || !items.length ? "…" : (totalVulns / items.length).toFixed(1)}
          </p>
        </Card>
      </div>

      <div className="mt-4 grid lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Theo severity (highest)</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-48" />
            ) : (
              <Suspense fallback={<Skeleton className="h-48" />}>
                <SeverityChart data={bySev} />
              </Suspense>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Theo ngôn ngữ</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-48" />
            ) : (
              <Suspense fallback={<Skeleton className="h-48" />}>
                <SeverityChart data={byLang} />
              </Suspense>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
