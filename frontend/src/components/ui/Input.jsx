import { forwardRef } from "react";
import { cn } from "../../lib/utils";

export const Input = forwardRef(function Input(
  { className, label, error, hint, id, ...props },
  ref
) {
  const inputId = id || props.name;
  return (
    <label className="block space-y-1.5 text-sm">
      {label ? <span className="font-medium text-fg">{label}</span> : null}
      <input
        ref={ref}
        id={inputId}
        className={cn(
          "w-full h-10 rounded-lg border border-border bg-surface px-3 text-fg placeholder:text-muted/70 outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50",
          error && "border-danger focus:ring-danger/30",
          className
        )}
        {...props}
      />
      {error ? <span className="text-danger text-xs">{error}</span> : null}
      {hint && !error ? <span className="text-muted text-xs">{hint}</span> : null}
    </label>
  );
});

export const Textarea = forwardRef(function Textarea(
  { className, label, error, id, ...props },
  ref
) {
  const inputId = id || props.name;
  return (
    <label className="block space-y-1.5 text-sm">
      {label ? <span className="font-medium text-fg">{label}</span> : null}
      <textarea
        ref={ref}
        id={inputId}
        className={cn(
          "w-full min-h-[100px] rounded-lg border border-border bg-surface px-3 py-2 text-fg placeholder:text-muted/70 outline-none focus:ring-2 focus:ring-primary/30",
          error && "border-danger",
          className
        )}
        {...props}
      />
      {error ? <span className="text-danger text-xs">{error}</span> : null}
    </label>
  );
});

export function Select({ className, label, error, children, id, ...props }) {
  const inputId = id || props.name;
  return (
    <label className="block space-y-1.5 text-sm">
      {label ? <span className="font-medium text-fg">{label}</span> : null}
      <select
        id={inputId}
        className={cn(
          "w-full h-10 rounded-lg border border-border bg-surface px-3 text-fg outline-none focus:ring-2 focus:ring-primary/30",
          className
        )}
        {...props}
      >
        {children}
      </select>
      {error ? <span className="text-danger text-xs">{error}</span> : null}
    </label>
  );
}
