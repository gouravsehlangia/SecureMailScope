import { sevOf } from '../lib/severity';

export default function SeverityBadge({ level, size = 'md' }) {
  const sev = sevOf(level);
  const pad = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs';
  return (
    <span
      className={`inline-flex items-center gap-1.5 ${pad} font-mono font-medium tracking-wide uppercase border ${sev.border} ${sev.bg} ${sev.text}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
      {sev.label}
    </span>
  );
}
