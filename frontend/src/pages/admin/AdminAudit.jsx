import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { api } from "../../lib/api";
import { formatDate } from "../../lib/utils";
import { Card } from "../../components/ui/Card";
import { Skeleton } from "../../components/ui/Skeleton";

export default function AdminAudit() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .adminAudit()
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <Helmet>
        <title>Admin · Audit</title>
      </Helmet>
      <h1 className="text-2xl font-semibold">Audit logs</h1>
      <Card className="mt-4 overflow-x-auto">
        {loading ? (
          <div className="p-4">
            <Skeleton className="h-32" />
          </div>
        ) : rows.length === 0 ? (
          <p className="p-6 text-sm text-muted">Chưa có log</p>
        ) : (
          <ul className="divide-y divide-border text-sm">
            {rows.map((r) => (
              <li key={r.id} className="px-4 py-3">
                <div className="flex justify-between gap-2">
                  <span className="font-medium">{r.action || r.event || "event"}</span>
                  <span className="text-xs text-muted">{formatDate(r.created_at)}</span>
                </div>
                <p className="text-xs text-muted mt-1 font-mono">
                  user={r.user_id} · {r.detail || r.meta || r.message || ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
