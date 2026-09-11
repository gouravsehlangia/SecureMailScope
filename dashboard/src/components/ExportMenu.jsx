import { useState, useRef, useEffect } from 'react';
import { exportJson, exportHtml, exportPdfViaPrint } from '../lib/report';

export default function ExportMenu({ sessions }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  const actions = [
    { label: 'JSON', run: () => exportJson(sessions) },
    { label: 'HTML', run: () => exportHtml(sessions) },
    { label: 'PDF', run: () => exportPdfViaPrint(sessions) },
  ];

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="px-3 py-1.5 text-xs font-mono uppercase tracking-wide border border-[var(--color-ink-border)] text-[var(--color-text-primary)] hover:border-[var(--color-accent)] transition-colors"
      >
        Export ▾
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-32 bg-[var(--color-ink-800)] border border-[var(--color-ink-border)] z-20">
          {actions.map((a) => (
            <button
              key={a.label}
              onClick={() => { a.run(); setOpen(false); }}
              className="block w-full text-left px-3 py-2 text-xs font-mono text-[var(--color-text-muted)] hover:bg-[var(--color-ink-700)] hover:text-[var(--color-text-primary)]"
            >
              {a.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
