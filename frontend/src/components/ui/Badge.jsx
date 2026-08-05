import { cn } from "../../lib/utils";

export function Badge({ className, children, variant = "default" }) {
  const styles = {
    default: "bg-bg text-muted border-border",
    primary: "bg-primary/10 text-primary border-primary/25",
    success: "bg-success/10 text-success border-success/25",
    danger: "bg-danger/10 text-danger border-danger/25",
    accent: "bg-accent/10 text-accent border-accent/25",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        styles[variant] || styles.default,
        className
      )}
    >
      {children}
    </span>
  );
}
