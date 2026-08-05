import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { X } from "lucide-react";
import { cn } from "../../lib/utils";

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((t) => t.filter((x) => x.id !== id));
  }, []);

  const toast = useCallback(
    (message, opts = {}) => {
      const id = Math.random().toString(36).slice(2);
      const item = { id, message, variant: opts.variant || "default", duration: opts.duration ?? 2800 };
      setToasts((t) => [...t, item]);
      setTimeout(() => dismiss(id), item.duration);
      return id;
    },
    [dismiss]
  );

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              "animate-toast flex items-start gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-sm shadow-lg",
              t.variant === "danger" && "border-danger/40 text-danger",
              t.variant === "success" && "border-success/40 text-success"
            )}
          >
            <span className="flex-1 text-fg">{t.message}</span>
            <button type="button" onClick={() => dismiss(t.id)} className="text-muted hover:text-fg" aria-label="Đóng">
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
