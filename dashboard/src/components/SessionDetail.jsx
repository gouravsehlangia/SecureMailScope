import SeverityBadge from './SeverityBadge';

function Field({ label, children }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-1">
        {label}
      </div>
      <div className="text-sm font-mono text-[var(--color-text-primary)]">{children}</div>
    </div>
  );
}

export default function SessionDetail({ session, onClose }) {
  if (!session) return null;
  const s = session;

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative w-full max-w-[480px] h-full bg-[var(--color-ink-900)] border-l border-[var(--color-ink-border)] overflow-y-auto">
        <div className="sticky top-0 bg-[var(--color-ink-900)] border-b border-[var(--color-ink-border)] px-5 py-4 flex items-start justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono">
              Session Detail
            </div>
            <div className="text-lg font-mono text-[var(--color-text-primary)]">{s.session_id}</div>
          </div>
          <button
            onClick={onClose}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] text-xl leading-none px-1"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="p-5 space-y-6">
          <div className="flex items-center gap-3">
            <SeverityBadge level={s.risk_level} />
            <span className="font-mono text-sm text-[var(--color-text-muted)]">
              Risk score {s.risk_score}/100
            </span>
            {s.anomaly_flag && (
              <span className="font-mono text-xs text-[var(--color-accent)] border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 px-2 py-0.5">
                ANOMALY {s.anomaly_score?.toFixed?.(3) ?? s.anomaly_score}
              </span>
            )}
          </div>

          <section className="grid grid-cols-2 gap-4">
            <Field label="Protocol">{s.protocol}</Field>
            <Field label="STARTTLS">{s.starttls_used ? 'Used' : 'Not used'}</Field>
            <Field label="TLS Version">{s.tls_version}</Field>
            <Field label="Key Exchange">{s.key_exchange}</Field>
            <Field label="Forward Secrecy">
              <span className={s.forward_secrecy ? 'text-[var(--color-low)]' : 'text-[var(--color-crit)]'}>
                {s.forward_secrecy ? 'Yes' : 'No'}
              </span>
            </Field>
            <Field label="Handshake Duration">{s.handshake_duration_ms} ms</Field>
          </section>

          <section>
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-1">
              Cipher Suite
            </div>
            <div className="text-sm font-mono text-[var(--color-text-primary)] break-all">
              {s.cipher_suite}
            </div>
          </section>

          <section className="border-t border-[var(--color-ink-border)] pt-4 grid grid-cols-2 gap-4">
            <Field label="Cert Key Length">{s.cert_key_length} bits</Field>
            <Field label="Cert Chain">
              <span className={s.cert_chain_valid ? 'text-[var(--color-low)]' : 'text-[var(--color-crit)]'}>
                {s.cert_chain_valid ? 'Valid' : 'Invalid'}
              </span>
            </Field>
            <Field label="Cert Expiry">
              <span className={s.cert_expired ? 'text-[var(--color-crit)]' : 'text-[var(--color-low)]'}>
                {s.cert_expired ? 'Expired' : 'Not expired'}
              </span>
            </Field>
          </section>

          {s.rule_violations?.length > 0 && (
            <section className="border-t border-[var(--color-ink-border)] pt-4">
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-2">
                Rule Findings ({s.rule_violations.length})
              </div>
              <ul className="space-y-1.5">
                {s.rule_violations.map((v, i) => (
                  <li key={i} className="text-sm text-[var(--color-text-muted)] pl-3 border-l-2 border-[var(--color-crit)]/50">
                    {v}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {s.reasons?.length > 0 && (
            <section className="border-t border-[var(--color-ink-border)] pt-4">
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-2">
                Anomaly Signals
              </div>
              <ul className="space-y-1.5">
                {s.reasons.map((r, i) => (
                  <li key={i} className="text-sm text-[var(--color-text-muted)] pl-3 border-l-2 border-[var(--color-accent)]/50">
                    {r}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {s.ai_recommendation && (
            <section className="border-t border-[var(--color-ink-border)] pt-4">
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-2">
                AI Recommendation
              </div>
              <p className="text-sm text-[var(--color-text-primary)] leading-relaxed font-sans bg-[var(--color-ink-800)] border border-[var(--color-ink-border)] p-3">
                {s.ai_recommendation}
              </p>
            </section>
          )}

          {s.data_incomplete && (
            <div className="text-xs font-mono text-[var(--color-high)] border border-[var(--color-high)]/40 bg-[var(--color-high-bg)] px-3 py-2">
              This record had missing fields — one or more values were parsed with defaults.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
