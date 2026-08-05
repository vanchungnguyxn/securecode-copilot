import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

export function formatVnd(n) {
  if (n == null || Number.isNaN(n)) return "—";
  return new Intl.NumberFormat("vi-VN", {
    style: "currency",
    currency: "VND",
    maximumFractionDigits: 0,
  }).format(n);
}

export function formatDate(iso) {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("vi-VN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(iso));
}

export function severityColor(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "text-danger bg-danger/10 border-danger/30";
  if (s === "high") return "text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/30";
  if (s === "medium") return "text-amber-700 dark:text-amber-400 bg-amber-500/10 border-amber-500/30";
  if (s === "low") return "text-sky-700 dark:text-sky-400 bg-sky-500/10 border-sky-500/30";
  return "text-muted bg-muted/10 border-border";
}
