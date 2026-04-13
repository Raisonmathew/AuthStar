import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from './utils';

export interface ToggleProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'size'> {
  label?: string;
  description?: string;
  size?: 'sm' | 'md';
}

const Toggle = forwardRef<HTMLInputElement, ToggleProps>(
  ({ className, label, description, size = 'md', id, ...props }, ref) => {
    const inputId = id || `toggle-${Math.random().toString(36).slice(2, 9)}`;
    const trackSize = size === 'sm' ? 'h-5 w-9' : 'h-6 w-11';
    const thumbSize = size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4';
    const thumbTranslate = size === 'sm' ? 'peer-checked:translate-x-4' : 'peer-checked:translate-x-5';

    return (
      <label
        htmlFor={inputId}
        className={cn(
          'flex items-center justify-between gap-4 cursor-pointer select-none',
          className,
        )}
      >
        {(label || description) && (
          <div className="flex-1 min-w-0">
            {label && <span className="block text-sm font-medium text-foreground">{label}</span>}
            {description && <span className="block text-xs text-muted-foreground mt-0.5">{description}</span>}
          </div>
        )}
        <div className="relative inline-flex items-center flex-shrink-0">
          <input
            ref={ref}
            id={inputId}
            type="checkbox"
            className="peer sr-only"
            {...props}
          />
          <div
            className={cn(
              trackSize,
              'rounded-full border border-input bg-muted transition-colors peer-checked:bg-primary peer-checked:border-primary peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-focus-visible:ring-offset-2',
            )}
          />
          <div
            className={cn(
              thumbSize,
              thumbTranslate,
              'absolute left-1 top-1/2 -translate-y-1/2 rounded-full bg-background shadow-sm transition-transform duration-200',
            )}
          />
        </div>
      </label>
    );
  },
);
Toggle.displayName = 'Toggle';

export { Toggle };
