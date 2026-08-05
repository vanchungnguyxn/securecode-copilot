import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { api } from "../../lib/api";
import { formatDate } from "../../lib/utils";
import { Card } from "../../components/ui/Card";
import { Skeleton } from "../../components/ui/Skeleton";

export default function AdminAnalyses() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .adminAnalyses()
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <Helmet>
        <title>Admin · Analyses</title>
      </Helmet>
      <h1 className="text-2xl font-semibold">Phân tích (toàn hệ thống)</h1>
      <Card className="mt-4 overflow-x-auto">
        {loading ? (
          <div className="p-4">
            <Skeleton className="h-32" />
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-muted">
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">User</th>
                <th className="px-3 py-2">Project</th>
                <th className="px-3 py-2">Issues</th>
                <th className="px-3 py-2">Time</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-border">
                  <td className="px-3 py-2 font-mono text-xs">{r.id}</td>
                  <td className="px-3 py-2">{r.user_email || r.user_id}</td>
                  <td className="px-3 py-2">{r.project_name || r.filename}</td>
                  <td className="px-3 py-2">{r.vulnerability_count}</td>
                  <td className="px-3 py-2 text-xs text-muted">{formatDate(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
