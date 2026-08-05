import { useEffect, useMemo, useState, lazy, Suspense } from "react";
import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { ArrowRight, ScanSearch, AlertTriangle } from "lucide-react";
import { api } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { formatDate } from "../../lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { QuotaBar } from "../../components/ui/QuotaBar";
import { Badge } from "../../components/ui/Badge";
import { Skeleton } from "../../components/ui/Skeleton";

const SeverityChart = lazy(() => import("./SeverityChart"));

export default function Dashboard() {
  const { user, refresh } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    refresh();
    api
      .listAnalyses({ limit: 50 })
      .then(setItems)
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [refresh]);

  const stats = useMemo(() => {
    const total = items.length;
    const vulns = items.reduce((s, a) => s + (a.vulnerability_count || 0), 0);
    const critical = items.filter((a) => (a.highest_severity || "").toLowerCase() === "critical").length;
    const high = items.filter((a) => (a.highest_severity || "").toLowerCase() === "high").length;
    return { total, vulns, critical, high };
  }, [items]);

  const severityData = useMemo(() => {
    const map = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of items) {
      const s = (a.highest_severity || "info").toLowerCase();
      if (map[s] != null) map[s] += 1;
      else map.info += 1;
    }
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [items]);

  const recent = items.slice(0, 5);

  return (
    <div>
      <Helmet>
        <title>Tổng quan · SecureCode Copilot</title>
      </Helmet>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="section-kicker">Dashboard</p>
          <h1 className="mt-2 text-2xl sm:text-3xl font-semibold tracking-tight">
            Xin chào, {user?.full_name?.split(" ").pop()}
          </h1>
          <p className="text-sm text-muted mt-1.5">Theo dõi quota và phân tích gần đây</p>
        </div>
        <Link to="/dashboard/analyze">
          <Button>
            <ScanSearch className="h-4 w-4" /> Phân tích mới
          </Button>
        </Link>
      </div>

      <div className="mt-8 grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card hover className="p-5">
          <p className="text-xs text-muted uppercase tracking-wide">Gói hiện tại</p>
          <p className="mt-2 text-xl font-semibold capitalize tracking-tight">{user?.plan_name || user?.plan_code}</p>
          {user?.plan_code === "free" ? (
            <Link to="/dashboard/billing" className="text-xs text-primary mt-3 inline-flex items-center gap-1 hover:underline">
              Nâng cấp <ArrowRight className="h-3 w-3" />
            </Link>
          ) : null}
        </Card>
        <Card hover className="p-5">
          <p className="text-xs text-muted uppercase tracking-wide mb-3">Quota tháng này</p>
          <QuotaBar used={user?.used_this_month || 0} limit={user?.monthly_limit || 0} />
        </Card>
        <Card hover className="p-5">
          <p className="text-xs text-muted uppercase tracking-wide">Tổng phân tích</p>
          <p className="mt-2 text-xl font-semibold tracking-tight">{loading ? "…" : stats.total}</p>
        </Card>
        <Card hover className="p-5">
          <p className="text-xs text-muted uppercase tracking-wide">Findings (đã lưu)</p>
          <p className="mt-2 text-xl font-semibold tracking-tight">{loading ? "…" : stats.vulns}</p>
          {(stats.critical > 0 || stats.high > 0) && (
            <p className="text-xs text-danger mt-2 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              {stats.critical} crit · {stats.high} high (highest)
            </p>
          )}
        </Card>
      </div>

      <div className="mt-6 grid lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Severity (theo highest mỗi lần quét)</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-48" />
            ) : (
              <Suspense fallback={<Skeleton className="h-48" />}>
                <SeverityChart data={severityData} />
              </Suspense>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Gần đây</CardTitle>
            <Link to="/dashboard/history" className="text-xs text-primary hover:underline">
              Xem tất cả
            </Link>
          </CardHeader>
          <CardContent className="space-y-2">
            {loading ? (
              <>
                <Skeleton className="h-12" />
                <Skeleton className="h-12" />
              </>
            ) : recent.length === 0 ? (
              <p className="text-sm text-muted py-8 text-center">Chưa có phân tích. Bắt đầu quét code đầu tiên.</p>
            ) : (
              recent.map((a) => (
                <Link
                  key={a.id}
                  to={`/dashboard/history/${a.id}`}
                  className="flex items-center justify-between gap-3 rounded-xl border border-border px-3.5 py-3 hover:bg-fg/[0.03] hover:border-primary/25 text-sm transition-all duration-200"
                >
                  <div className="min-w-0">
                    <p className="font-medium truncate tracking-tight">{a.project_name || a.filename}</p>
                    <p className="text-xs text-muted mt-0.5">{formatDate(a.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-muted text-xs">{a.vulnerability_count} issues</span>
                    {a.highest_severity ? (
                      <Badge variant={a.highest_severity === "critical" || a.highest_severity === "high" ? "danger" : "default"}>
                        {a.highest_severity}
                      </Badge>
                    ) : null}
                  </div>
                </Link>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
