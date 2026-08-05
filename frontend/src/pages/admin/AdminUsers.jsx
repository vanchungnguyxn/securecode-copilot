import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { api } from "../../lib/api";
import { formatDate } from "../../lib/utils";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Input } from "../../components/ui/Input";
import { Skeleton } from "../../components/ui/Skeleton";
import { useToast } from "../../components/ui/Toast";

export default function AdminUsers() {
  const { toast } = useToast();
  const [q, setQ] = useState("");
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  async function load(query = q) {
    setLoading(true);
    try {
      setUsers(await api.adminUsers({ q: query || undefined, limit: 100 }));
    } catch (e) {
      toast(e.message, { variant: "danger" });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function toggleLock(u) {
    await api.adminLockUser(u.id, !u.is_locked);
    toast(u.is_locked ? "Đã mở khóa" : "Đã khóa");
    load();
  }

  async function addQuota(u) {
    const delta = Number(prompt("Thêm bao nhiêu lượt remaining? (delta âm vào used hoặc set_limit)", "10"));
    if (!Number.isFinite(delta)) return;
    await api.adminAdjustQuota(u.id, { delta });
    toast("Đã điều chỉnh quota");
    load();
  }

  return (
    <div>
      <Helmet>
        <title>Admin · Users</title>
      </Helmet>
      <h1 className="text-2xl font-semibold">Người dùng</h1>
      <form
        className="mt-4 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          load();
        }}
      >
        <Input className="flex-1" placeholder="Tìm email / tên…" value={q} onChange={(e) => setQ(e.target.value)} />
        <Button type="submit">Tìm</Button>
      </form>

      <Card className="mt-4 overflow-x-auto">
        {loading ? (
          <div className="p-4">
            <Skeleton className="h-40" />
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-muted">
                <th className="px-3 py-2 font-medium">User</th>
                <th className="px-3 py-2 font-medium">Role</th>
                <th className="px-3 py-2 font-medium">Plan</th>
                <th className="px-3 py-2 font-medium">Quota</th>
                <th className="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-border">
                  <td className="px-3 py-2">
                    <p className="font-medium">{u.full_name}</p>
                    <p className="text-xs text-muted">{u.email}</p>
                    <p className="text-[10px] text-muted">{formatDate(u.created_at)}</p>
                  </td>
                  <td className="px-3 py-2">{u.role}</td>
                  <td className="px-3 py-2">{u.plan}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {u.used_this_month}/{u.monthly_limit}
                    {u.is_locked ? <span className="text-danger ml-1">locked</span> : null}
                  </td>
                  <td className="px-3 py-2 space-x-1">
                    <Button size="sm" variant="secondary" onClick={() => toggleLock(u)}>
                      {u.is_locked ? "Unlock" : "Lock"}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => addQuota(u)}>
                      Quota
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
