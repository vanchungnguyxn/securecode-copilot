import { cn } from "../../lib/utils";

export function QuotaBar({ used = 0, limit = 0, className, compact }) {
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const remaining = Math.max(0, limit - used);
  const danger = pct >= 90;
  const warn = pct >= 70 && !danger;

  return (
    <div className={cn("space-y-1", className)}>
      {!compact ? (
        <div className="flex justify-between text-xs text-muted">
          <span>
            Đã dùng {used}/{limit}
          </span>
          <span>{remaining} còn lại</span>
        </div>
      ) : (
        <div className="text-xs text-muted whitespace-nowrap">
          {used}/{limit} lượt
        </div>
      )}
      <div className="h-1.5 rounded-full bg-border/80 overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            danger ? "bg-danger" : warn ? "bg-amber-500" : "bg-primary"
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
