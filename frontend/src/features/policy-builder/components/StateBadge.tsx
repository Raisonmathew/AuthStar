import { clsx } from 'clsx';
import type { ConfigSummary } from '../types';

type State = ConfigSummary['state'];

interface StateBadgeProps {
  state: State;
  version?: number | null;
  className?: string;
}

const config: Record<State, { label: string; classes: string }> = {
  draft: {
    label: 'DRAFT',
    classes: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
  },
  compiled: {
    label: 'COMPILED',
    classes: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  },
  active: {
    label: 'ACTIVE',
    classes: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
  },
  archived: {
    label: 'ARCHIVED',
    classes: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  },
};

export function StateBadge({ state, version, className }: StateBadgeProps) {
  const { label, classes } = config[state] ?? config.draft;
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold tracking-wide',
        classes,
        className
      )}
    >
      {state === 'active' && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
        </span>
      )}
      {label}
      {version != null && ` v${version}`}
    </span>
  );
}