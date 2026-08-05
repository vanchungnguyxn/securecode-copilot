import { cn } from "../../lib/utils";

export function Skeleton({ className }) {
  return <div className={cn("skeleton h-4 w-full", className)} aria-hidden />;
}

export function PageSkeleton() {
  return (
    <div className="space-y-4 p-1">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-4 w-72" />
      <div className="grid gap-4 sm:grid-cols-3">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}
