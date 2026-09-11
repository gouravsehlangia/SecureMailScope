import ExportMenu from './ExportMenu';

export default function TopBar({ source, onRefresh, sessions }) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-ink-border)]">
      <div>
        <h1 className="text-base font-semibold tracking-tight text-[var(--color-text-primary)]">
          SecureMailScope
        </h1>
        <p className="text-[11px] font-mono text-[var(--color-text-dim)] mt-0.5">
          Cryptographic security posture — SMTP / IMAP / POP3
        </p>
      </div>

      <div className="flex items-center gap-3">
        <span
          className={`flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 border ${
            source === 'live'
              ? 'border-[var(--color-low)]/40 text-[var(--color-low)] bg-[var(--color-low-bg)]'
              : 'border-[var(--color-high)]/40 text-[var(--color-high)] bg-[var(--color-high-bg)]'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${source === 'live' ? 'bg-[var(--color-low)]' : 'bg-[var(--color-high)]'}`} />
          {source === 'live' ? 'Live backend' : 'Sample data (backend offline)'}
        </span>
        <button
          onClick={onRefresh}
          className="px-3 py-1.5 text-xs font-mono uppercase tracking-wide border border-[var(--color-ink-border)] text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors"
        >
          Refresh
        </button>
        <ExportMenu sessions={sessions} />
      </div>
    </div>
  );
}
