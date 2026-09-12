export default function QuickStatsWidget({ sessions = [] }) {
  // Compute dynamically from sessions
  let certIssues = 0;
  let weakCrypto = 0;
  let pfsIssues = 0;
  let anomalies = 0;

  if (sessions.length > 0) {
    for (const s of sessions) {
      if (s.cert_expired || !s.cert_chain_valid || (s.cert_key_length && s.cert_key_length < 2048)) {
        certIssues++;
      }
      if (s.tls_version === 'TLS 1.0' || s.tls_version === 'TLS 1.1' || (s.cipher_suite && s.cipher_suite.includes('3DES'))) {
        weakCrypto++;
      }
      if (s.forward_secrecy === false) {
        pfsIssues++;
      }
      if (s.anomaly_flag) {
        anomalies++;
      }
    }
  } else {
    certIssues = 3;
    weakCrypto = 2;
    pfsIssues = 1;
    anomalies = 2;
  }

  const items = [
    {
      id: 'cert',
      label: 'Certificate Issues',
      count: certIssues,
      icon: (
        <svg className="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
      bg: 'bg-amber-50/80',
    },
    {
      id: 'crypto',
      label: 'Weak / Deprecated Crypto',
      count: weakCrypto,
      icon: (
        <svg className="w-4 h-4 text-rose-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
      bg: 'bg-rose-50/80',
    },
    {
      id: 'pfs',
      label: 'Forward Secrecy Issues',
      count: pfsIssues,
      icon: (
        <svg className="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      ),
      bg: 'bg-purple-50/80',
    },
    {
      id: 'anomalies',
      label: 'Anomalies Detected',
      count: anomalies,
      icon: (
        <svg className="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
      bg: 'bg-sky-50/80',
    },
  ];

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title */}
      <div className="flex items-center gap-2 mb-4">
        <div className="w-6 h-6 rounded-lg bg-sky-100 flex items-center justify-center text-sky-600">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
          </svg>
        </div>
        <h3 className="text-xs font-bold text-slate-800 tracking-tight">
          Quick Stats
        </h3>
      </div>

      {/* List */}
      <div className="space-y-3">
        {items.map((item) => (
          <div
            key={item.id}
            className="flex items-center justify-between p-2 rounded-xl hover:bg-white/60 transition-colors"
          >
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-xl ${item.bg} flex items-center justify-center shadow-xs`}>
                {item.icon}
              </div>
              <span className="text-xs font-medium text-slate-700">
                {item.label}
              </span>
            </div>
            <span className="font-mono font-bold text-sm text-slate-800 px-2.5 py-0.5 rounded-lg bg-white/70 border border-white shadow-xs">
              {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
