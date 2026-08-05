import { cn } from "../../lib/utils";

const variants = {
  primary:
    "bg-primary text-primary-fg hover:brightness-110 active:brightness-95 shadow-[0_1px_0_rgba(255,255,255,0.12)_inset]",
  secondary: "bg-surface/90 text-fg border border-border hover:bg-bg hover:border-primary/25",
  ghost: "text-muted hover:text-fg hover:bg-fg/5",
  danger: "bg-danger text-white hover:brightness-110",
  accent: "bg-accent text-white hover:brightness-110",
  outline: "border border-border bg-transparent text-fg hover:bg-surface hover:border-primary/30",
};

const sizes = {
  sm: "h-8 px-3 text-sm gap-1.5",
  md: "h-10 px-4 text-sm gap-2",
  lg: "h-11 px-6 text-[0.95rem] gap-2",
  icon: "h-9 w-9 p-0",
};

export function Button({
  className,
  variant = "primary",
  size = "md",
  loading,
  disabled,
  children,
  type = "button",
  ...props
}) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center rounded-lg font-medium transition-all duration-200 ease-out",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
        "disabled:opacity-50 disabled:pointer-events-none",
        variants[variant],
        sizes[size],
        className
      )}
      {...props}
    >
      {loading ? (
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent" />
      ) : null}
      {children}
    </button>
  );
}
