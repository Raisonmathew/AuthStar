import { cn } from './utils';

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div className={cn('animate-pulse rounded-lg bg-muted', className)} />
  );
}

export function CardSkeleton({ className }: SkeletonProps) {
  return (
    <div className={cn('rounded-2xl border border-border bg-card p-6 space-y-4 animate-pulse', className)}>
      <div className="flex items-start justify-between">
        <div className="space-y-2.5">
          <div className="h-3 w-24 rounded bg-muted" />
          <div className="h-7 w-16 rounded bg-muted" />
        </div>
        <div className="h-10 w-10 rounded-xl bg-muted" />
      </div>
      <div className="h-3 w-32 rounded bg-muted" />
    </div>
  );
}
