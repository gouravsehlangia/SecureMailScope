// Mirrors risk_scoring.py get_risk_level() exactly:
// >=75 critical, >=50 high, >=25 medium, else low.

export const SEVERITY = {
  critical: {
    label: 'Critical',
    text: 'text-[#f4565b]',
    bg: 'bg-[rgba(244,86,91,0.12)]',
    border: 'border-[rgba(244,86,91,0.3)]',
    dot: 'bg-[#f4565b]',
    hex: '#f4565b',
    rank: 3,
  },
  high: {
    label: 'High',
    text: 'text-[#fb923c]',
    bg: 'bg-[rgba(251,146,60,0.12)]',
    border: 'border-[rgba(251,146,60,0.3)]',
    dot: 'bg-[#fb923c]',
    hex: '#fb923c',
    rank: 2,
  },
  medium: {
    label: 'Medium',
    text: 'text-[#fbbf24]',
    bg: 'bg-[rgba(251,191,36,0.12)]',
    border: 'border-[rgba(251,191,36,0.3)]',
    dot: 'bg-[#fbbf24]',
    hex: '#fbbf24',
    rank: 1,
  },
  low: {
    label: 'Low',
    text: 'text-[#34d399]',
    bg: 'bg-[rgba(52,211,153,0.12)]',
    border: 'border-[rgba(52,211,153,0.3)]',
    dot: 'bg-[#34d399]',
    hex: '#34d399',
    rank: 0,
  },
};

export function sevOf(level) {
  return SEVERITY[level] || SEVERITY.low;
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
