import { sevOf } from '../lib/severity';

export default function SeverityBadge({ level, size = 'md' }) {
  const BADGE = {
    critical: 'bg-rose-50 border-rose-200 text-rose-700',
    high:     'bg-orange-50 border-orange-200 text-orange-700',
    medium:   'bg-amber-50 border-amber-200 text-amber-700',
    low:      'bg-emerald-50 border-emerald-200 text-emerald-700',
  };
  const DOT = {
    critical: 'bg-rose-500',
    high:     'bg-orange-400',
    medium:   'bg-amber-400',
    low:      'bg-emerald-500',
  };
  const label = { critical:'Critical', high:'High', medium:'Medium', low:'Low' };
  const pad = size === 'sm' ? 'px-2 py-0.5 text-[10px] gap-1' : 'px-2.5 py-1 text-[11px] gap-1.5';
  return (
    <span className={`inline-flex items-center ${pad} rounded-full font-semibold tracking-wide uppercase border font-mono ${BADGE[level] || BADGE.low}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT[level] || DOT.low}`} />
      {label[level] || level}
    </span>
  );
}
