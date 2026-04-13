/**
 * ParamForm — renders a form from a JSON Schema object.
 * Supports: number/integer (input + slider), string, boolean (toggle),
 * string enum (select), array of strings (tag input), array of enum (checkboxes).
 *
 * onChange is called with the full updated params object on every change.
 */

import { useState } from 'react';
import { clsx } from 'clsx';

interface ParamFormProps {
  schema: Record<string, any>;
  defaults: Record<string, any>;
  values: Record<string, any>;
  onChange: (values: Record<string, any>) => void;
  disabled?: boolean;
}

// ─── Field-level components ───────────────────────────────────────────────────

function NumberField({
  name,
  schema,
  value,
  onChange,
  disabled,
}: {
  name: string;
  schema: any;
  value: any;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const min = schema.minimum ?? 0;
  const max = schema.maximum ?? undefined;
  const hasRange = schema.minimum !== undefined && schema.maximum !== undefined;
  const numVal = typeof value === 'number' ? value : (schema.default ?? min);

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <label className="text-xs font-medium text-foreground capitalize">
          {name.replace(/_/g, ' ')}
        </label>
        <span className="text-xs text-muted-foreground font-mono">{numVal}</span>
      </div>
      {hasRange ? (
        <div className="space-y-1">
          <input
            type="range"
            min={min}
            max={max}
            step={schema.type === 'integer' ? 1 : 0.1}
            value={numVal}
            onChange={(e) => onChange(Number(e.target.value))}
            disabled={disabled}
            className="w-full h-1.5 bg-muted rounded-full appearance-none cursor-pointer accent-primary disabled:opacity-50"
          />
          <div className="flex justify-between text-[10px] text-muted-foreground">
            <span>{min}</span>
            <span>{max}</span>
          </div>
        </div>
      ) : (
        <input
          type="number"
          min={min}
          max={max}
          value={numVal}
          onChange={(e) => onChange(Number(e.target.value))}
          disabled={disabled}
          className="w-full bg-muted border border-border rounded-lg px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
        />
      )}
      {schema.description && (
        <p className="text-[11px] text-muted-foreground">{schema.description}</p>
      )}
    </div>
  );
}

function StringField({
  name,
  schema,
  value,
  onChange,
  disabled,
}: {
  name: string;
  schema: any;
  value: any;
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  const strVal = typeof value === 'string' ? value : '';

  if (schema.enum) {
    return (
      <div className="space-y-1">
        <label className="text-xs font-medium text-foreground capitalize">
          {name.replace(/_/g, ' ')}
        </label>
        <select
          value={strVal}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          className="w-full bg-muted border border-border rounded-lg px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
        >
          {schema.enum.map((opt: string) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        {schema.description && (
          <p className="text-[11px] text-muted-foreground">{schema.description}</p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-foreground capitalize">
        {name.replace(/_/g, ' ')}
      </label>
      <input
        type="text"
        value={strVal}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        placeholder={schema.description ?? ''}
        className="w-full bg-muted border border-border rounded-lg px-3 py-1.5 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
      />
      {schema.description && (
        <p className="text-[11px] text-muted-foreground">{schema.description}</p>
      )}
    </div>
  );
}

function BooleanField({
  name,
  value,
  onChange,
  disabled,
}: {
  name: string;
  value: any;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const boolVal = typeof value === 'boolean' ? value : false;
  return (
    <div className="flex items-center justify-between">
      <label className="text-xs font-medium text-foreground capitalize">
        {name.replace(/_/g, ' ')}
      </label>
      <button
        type="button"
        role="switch"
        aria-checked={boolVal}
        onClick={() => !disabled && onChange(!boolVal)}
        disabled={disabled}
        className={clsx(
          'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-card disabled:opacity-50',
          boolVal ? 'bg-primary' : 'bg-muted'
        )}
      >
        <span
          className={clsx(
            'inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform',
            boolVal ? 'translate-x-4' : 'translate-x-1'
          )}
        />
      </button>
    </div>
  );
}

function TagArrayField({
  name,
  schema,
  value,
  onChange,
  disabled,
}: {
  name: string;
  schema: any;
  value: any;
  onChange: (v: string[]) => void;
  disabled?: boolean;
}) {
  const [input, setInput] = useState('');
  const tags: string[] = Array.isArray(value) ? value : [];

  const addTag = (tag: string) => {
    const trimmed = tag.trim().toUpperCase();
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed]);
    }
    setInput('');
  };

  const removeTag = (tag: string) => {
    onChange(tags.filter((t) => t !== tag));
  };

  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-foreground capitalize">
        {name.replace(/_/g, ' ')}
      </label>
      <div className="flex flex-wrap gap-1.5 p-2 bg-muted border border-border rounded-lg min-h-[38px]">
        {tags.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 px-2 py-0.5 bg-primary/20 text-primary rounded text-xs font-mono"
          >
            {tag}
            {!disabled && (
              <button
                type="button"
                onClick={() => removeTag(tag)}
                className="text-primary hover:text-foreground leading-none"
                aria-label={`Remove ${tag}`}
              >
                ×
              </button>
            )}
          </span>
        ))}
        {!disabled && (
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                addTag(input);
              } else if (e.key === 'Backspace' && !input && tags.length > 0) {
                removeTag(tags[tags.length - 1]);
              }
            }}
            onBlur={() => input && addTag(input)}
            placeholder={tags.length === 0 ? (schema.description ?? 'Type and press Enter') : ''}
            className="flex-1 min-w-[80px] bg-transparent text-sm text-foreground placeholder-muted-foreground focus:outline-none"
          />
        )}
      </div>
      {schema.description && (
        <p className="text-[11px] text-muted-foreground">{schema.description}</p>
      )}
    </div>
  );
}

function EnumArrayField({
  name,
  schema,
  value,
  onChange,
  disabled,
}: {
  name: string;
  schema: any;
  value: any;
  onChange: (v: string[]) => void;
  disabled?: boolean;
}) {
  const selected: string[] = Array.isArray(value) ? value : [];
  const options: string[] = schema.items?.enum ?? [];

  const toggle = (opt: string) => {
    if (selected.includes(opt)) {
      onChange(selected.filter((s) => s !== opt));
    } else {
      onChange([...selected, opt]);
    }
  };

  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-foreground capitalize">
        {name.replace(/_/g, ' ')}
      </label>
      <div className="flex flex-wrap gap-2">
        {options.map((opt) => (
          <button
            key={opt}
            type="button"
            onClick={() => !disabled && toggle(opt)}
            disabled={disabled}
            className={clsx(
              'px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors disabled:opacity-50',
              selected.includes(opt)
                ? 'bg-primary/20 border-primary/40 text-primary'
                : 'bg-muted border-border text-muted-foreground hover:border-muted-foreground'
            )}
          >
            {opt}
          </button>
        ))}
      </div>
      {schema.description && (
        <p className="text-[11px] text-muted-foreground">{schema.description}</p>
      )}
    </div>
  );
}

function IntegerRadioField({
  name,
  schema,
  value,
  onChange,
  disabled,
}: {
  name: string;
  schema: any;
  value: any;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const min = schema.minimum ?? 1;
  const max = schema.maximum ?? 3;
  const numVal = typeof value === 'number' ? value : min;

  const labels: Record<number, string> = {
    1: 'Password only',
    2: 'Password + MFA',
    3: 'Hardware key',
  };

  const options = Array.from({ length: max - min + 1 }, (_, i) => min + i);

  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-foreground capitalize">
        {name.replace(/_/g, ' ')}
      </label>
      <div className="space-y-1.5">
        {options.map((opt) => (
          <label
            key={opt}
            className={clsx(
              'flex items-center gap-2.5 p-2 rounded-lg border cursor-pointer transition-colors',
              numVal === opt
                ? 'border-primary/40 bg-primary/10'
                : 'border-border bg-muted/50 hover:border-muted-foreground',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
          >
            <input
              type="radio"
              name={name}
              value={opt}
              checked={numVal === opt}
              onChange={() => !disabled && onChange(opt)}
              disabled={disabled}
              className="accent-primary"
            />
            <span className="text-sm text-foreground">
              <span className="font-mono font-semibold">{opt}</span>
              {labels[opt] && (
                <span className="text-muted-foreground ml-2">— {labels[opt]}</span>
              )}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}

// ─── Main ParamForm ───────────────────────────────────────────────────────────

export function ParamForm({ schema, defaults, values, onChange, disabled }: ParamFormProps) {
  const properties: Record<string, any> = schema?.properties ?? {};

  if (Object.keys(properties).length === 0) {
    return (
      <p className="text-xs text-muted-foreground italic">No parameters required for this template.</p>
    );
  }

  const handleChange = (key: string, val: any) => {
    onChange({ ...values, [key]: val });
  };

  const getValue = (key: string) => {
    if (values[key] !== undefined) return values[key];
    if (defaults[key] !== undefined) return defaults[key];
    return undefined;
  };

  return (
    <div className="space-y-4">
      {Object.entries(properties).map(([key, propSchema]) => {
        const val = getValue(key);

        // Special case: AAL level (integer 1-3) → radio buttons
        if (key === 'level' && propSchema.type === 'integer' && propSchema.minimum === 1 && propSchema.maximum === 3) {
          return (
            <IntegerRadioField
              key={key}
              name={key}
              schema={propSchema}
              value={val}
              onChange={(v) => handleChange(key, v)}
              disabled={disabled}
            />
          );
        }

        // Array field
        if (propSchema.type === 'array') {
          const itemSchema = propSchema.items ?? {};
          if (itemSchema.enum) {
            return (
              <EnumArrayField
                key={key}
                name={key}
                schema={propSchema}
                value={val}
                onChange={(v) => handleChange(key, v)}
                disabled={disabled}
              />
            );
          }
          return (
            <TagArrayField
              key={key}
              name={key}
              schema={propSchema}
              value={val}
              onChange={(v) => handleChange(key, v)}
              disabled={disabled}
            />
          );
        }

        // Boolean
        if (propSchema.type === 'boolean') {
          return (
            <BooleanField
              key={key}
              name={key}
              value={val}
              onChange={(v) => handleChange(key, v)}
              disabled={disabled}
            />
          );
        }

        // Number / integer
        if (propSchema.type === 'number' || propSchema.type === 'integer') {
          return (
            <NumberField
              key={key}
              name={key}
              schema={propSchema}
              value={val}
              onChange={(v) => handleChange(key, v)}
              disabled={disabled}
            />
          );
        }

        // String (with or without enum)
        return (
          <StringField
            key={key}
            name={key}
            schema={propSchema}
            value={val}
            onChange={(v) => handleChange(key, v)}
            disabled={disabled}
          />
        );
      })}
    </div>
  );
}