import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#0284c7",
  info: "#64748b",
};

export default function SeverityChart({ data }) {
  const filtered = (data || []).filter((d) => d.value > 0);
  if (!filtered.length) {
    return <p className="text-sm text-muted py-16 text-center">Chưa đủ dữ liệu biểu đồ</p>;
  }
  return (
    <div className="h-48 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={filtered}>
          <XAxis dataKey="name" tick={{ fontSize: 11 }} />
          <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={28} />
          <Tooltip />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {filtered.map((d) => (
              <Cell key={d.name} fill={COLORS[d.name] || "#6366f1"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
