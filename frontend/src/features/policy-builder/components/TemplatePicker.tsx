/**
 * TemplatePicker — slide-over panel for browsing and selecting rule templates.
 * Groups templates by category. Supports search filtering.
 */

import { useState, useEffect, useRef } from 'react';
import { clsx } from 'clsx';
import type { TemplateItem } from '../types';

interface TemplatePickerProps {
  templates: TemplateItem[];
  onSelect: (template: TemplateItem) => void;
  onClose: () => void;
}

// Category display order and labels
const CATEGORY_ORDER = [
  'risk',
  'location',
  'device',
  'network',
  'authentication',
  'time',
  'identity',
  'custom',
];

const CATEGORY_LABELS: Record<string, string> = {
  risk: 'Risk',
  location: 'Location',
  device: 'Device',
  network: 'Network',
  authentication: 'Authentication',
  time: 'Time',
  identity: 'Identity',
  custom: 'Custom',
};

export function TemplatePicker({ templates, onSelect, onClose }: TemplatePickerProps) {
  const [search, setSearch] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);

  // Focus search on open
  useEffect(() => {
    searchRef.current?.focus();
  }, []);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const filtered = templates.filter((t) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      t.display_name.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q)
    );
  });

  // Group by category
  const grouped = filtered.reduce<Record<string, TemplateItem[]>>((acc, t) => {
    const cat = t.category.toLowerCase();
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(t);
    return acc;
  }, {});

  // Sort categories by defined order, then alphabetically for unknowns
  const sortedCategories = [
    ...CATEGORY_ORDER.filter((c) => grouped[c]),
    ...Object.keys(grouped)
      .filter((c) => !CATEGORY_ORDER.includes(c))
      .sort(),
  ];

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over panel */}
      <div
        className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-card border-l border-border flex flex-col shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Choose a rule template"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h2 className="text-base font-semibold text-foreground">Choose a Rule Template</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Select a template to add a rule to this group
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Search */}
        <div className="px-4 py-3 border-b border-border">
          <div className="relative">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              ref={searchRef}
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search templates..."
              className="w-full bg-muted border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Clear search"
              >
                ×
              </button>
            )}
          </div>
        </div>

        {/* Template list */}
        <div className="flex-1 overflow-y-auto py-2">
          {sortedCategories.length === 0 ? (
            <div className="px-5 py-8 text-center">
              <p className="text-muted-foreground text-sm">No templates match "{search}"</p>
            </div>
          ) : (
            sortedCategories.map((cat) => (
              <div key={cat} className="mb-2">
                <div className="px-5 py-2">
                  <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">
                    {CATEGORY_LABELS[cat] ?? cat}
                  </span>
                </div>
                <div className="space-y-0.5 px-2">
                  {grouped[cat].map((template) => (
                    <TemplateCard
                      key={template.slug}
                      template={template}
                      onSelect={() => onSelect(template)}
                    />
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}

function TemplateCard({
  template,
  onSelect,
}: {
  template: TemplateItem;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={clsx(
        'w-full text-left px-3 py-3 rounded-xl transition-all group',
        'hover:bg-accent focus:outline-none focus:bg-accent',
        template.is_deprecated && 'opacity-50'
      )}
    >
      <div className="flex items-start gap-3">
        <span className="text-xl leading-none mt-0.5 flex-shrink-0">
          {template.icon ?? '⚙️'}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-foreground group-hover:text-foreground">
              {template.display_name}
            </span>
            {template.is_deprecated && (
              <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/10 text-amber-400 rounded border border-amber-500/20">
                Deprecated
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{template.description}</p>
          {template.is_deprecated && template.deprecated_reason && (
            <p className="text-xs text-amber-400/70 mt-1">⚠ {template.deprecated_reason}</p>
          )}
        </div>
        <svg
          className="w-4 h-4 text-muted-foreground group-hover:text-muted-foreground flex-shrink-0 mt-0.5 transition-colors"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </button>
  );
}