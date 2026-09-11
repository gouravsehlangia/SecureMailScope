// Mirrors risk_scoring.py get_risk_level() exactly:
// >=75 critical, >=50 high, >=25 medium, else low.

export const SEVERITY = {
  critical: {
    label: 'Critical',
    text: 'text-[var(--color-crit)]',
    bg: 'bg-[var(--color-crit-bg)]',
    border: 'border-[var(--color-crit)]/40',
    dot: 'bg-[var(--color-crit)]',
    rank: 3,
  },
  high: {
    label: 'High',
    text: 'text-[var(--color-high)]',
    bg: 'bg-[var(--color-high-bg)]',
    border: 'border-[var(--color-high)]/40',
    dot: 'bg-[var(--color-high)]',
    rank: 2,
  },
  medium: {
    label: 'Medium',
    text: 'text-[var(--color-med)]',
    bg: 'bg-[var(--color-med-bg)]',
    border: 'border-[var(--color-med)]/40',
    dot: 'bg-[var(--color-med)]',
    rank: 1,
  },
  low: {
    label: 'Low',
    text: 'text-[var(--color-low)]',
    bg: 'bg-[var(--color-low-bg)]',
    border: 'border-[var(--color-low)]/40',
    dot: 'bg-[var(--color-low)]',
    rank: 0,
  },
};

export function sevOf(level) {
  return SEVERITY[level] || SEVERITY.low;
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
