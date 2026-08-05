import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { api } from "../../lib/api";
import { formatVnd, formatDate } from "../../lib/utils";
import { Card } from "../../components/ui/Card";
import { Skeleton } from "../../components/ui/Skeleton";

export default function AdminPayments() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .adminPayments()
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <Helmet>
        <title>Admin · Payments</title>
      </Helmet>
      <h1 className="text-2xl font-semibold">Thanh toán</h1>
      <Card className="mt-4 overflow-x-auto">
        {loading ? (
          <div className="p-4">
            <Skeleton className="h-32" />
          </div>
        ) : rows.length === 0 ? (
          <p className="p-6 text-sm text-muted">Không có giao dịch</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-muted">
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">User</th>
                <th className="px-3 py-2">Amount</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Time</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-border">
                  <td className="px-3 py-2 font-mono text-xs">{r.id}</td>
                  <td className="px-3 py-2">{r.user_email || r.user_id}</td>
                  <td className="px-3 py-2">{formatVnd(r.amount)}</td>
                  <td className="px-3 py-2">{r.status}</td>
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
