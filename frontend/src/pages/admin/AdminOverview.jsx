import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { api } from "../../lib/api";
import { formatVnd } from "../../lib/utils";
import { Card } from "../../components/ui/Card";
import { PageSkeleton } from "../../components/ui/Skeleton";

export default function AdminOverview() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .adminStats()
      .then(setStats)
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="text-danger">{error}</p>;
  if (!stats) return <PageSkeleton />;

  const tiles = [
    { label: "Người dùng", value: stats.total_users },
    { label: "Paying", value: stats.paying_users },
    { label: "Phân tích", value: stats.total_analyses },
    { label: "Doanh thu (ước tính)", value: formatVnd(stats.mrr_estimate_vnd) },
    { label: "Pay thất bại", value: stats.failed_payments },
    { label: "AI cost ước tính", value: formatVnd(stats.ai_cost_estimate_vnd) },
  ];

  return (
    <div>
      <Helmet>
        <title>Admin · Tổng quan</title>
      </Helmet>
      <h1 className="text-2xl font-semibold">Tổng quan admin</h1>
      <div className="mt-6 grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {tiles.map((t) => (
          <Card key={t.label} className="p-4">
            <p className="text-xs text-muted">{t.label}</p>
            <p className="text-xl font-semibold mt-1">{t.value}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
