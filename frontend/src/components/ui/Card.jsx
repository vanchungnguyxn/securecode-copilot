import { cn } from "../../lib/utils";

export function Card({ className, hover, children, ...props }) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-surface",
        "shadow-[0_1px_0_rgba(15,23,42,0.03)]",
        hover && "surface-hover",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ className, children }) {
  return <div className={cn("px-5 pt-5 pb-2", className)}>{children}</div>;
}

export function CardTitle({ className, children }) {
  return <h3 className={cn("text-base font-semibold tracking-tight", className)}>{children}</h3>;
}

export function CardDescription({ className, children }) {
  return <p className={cn("text-sm text-muted mt-1 leading-relaxed", className)}>{children}</p>;
}

export function CardContent({ className, children }) {
  return <div className={cn("px-5 pb-5", className)}>{children}</div>;
}
