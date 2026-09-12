import { sevOf } from './severity';

function esc(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

const SEV_HEX = { critical: '#e5484d', high: '#f0883e', medium: '#e8b339', low: '#2fb88d' };

export function buildHtmlReport(sessions, meta = {}) {
  const generatedAt = new Date().toLocaleString();
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  sessions.forEach((s) => { counts[s.risk_level] = (counts[s.risk_level] || 0) + 1; });
  const anomalies = sessions.filter((s) => s.anomaly_flag).length;

  const rows = sessions
    .slice()
    .sort((a, b) => b.risk_score - a.risk_score)
    .map((s) => `
      <tr>
        <td>${esc(s.session_id)}</td>
        <td>${esc(s.protocol)}</td>
        <td>${esc(s.tls_version)}</td>
        <td>${esc(s.cipher_suite)}</td>
        <td>${s.forward_secrecy ? 'Yes' : 'No'}</td>
        <td>${!s.cert_expired && s.cert_chain_valid ? 'Valid' : 'Issue'}</td>
        <td>${s.risk_score}</td>
        <td><span class="badge" style="background:${SEV_HEX[s.risk_level]}22;color:${SEV_HEX[s.risk_level]};border:1px solid ${SEV_HEX[s.risk_level]}66">${esc(sevOf(s.risk_level).label)}</span></td>
        <td>${s.anomaly_flag ? 'Yes' : '—'}</td>
      </tr>
      ${s.rule_violations?.length ? `<tr class="findings-row"><td colspan="9"><strong>Findings:</strong> ${s.rule_violations.map(esc).join(' · ')}</td></tr>` : ''}
      ${s.ai_recommendation ? `<tr class="findings-row"><td colspan="9"><strong>AI recommendation:</strong> ${esc(s.ai_recommendation)}</td></tr>` : ''}
    `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SecureMailScope — Security Posture Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 36px; font-size: 13px; line-height: 1.5; }
  h1 { font-size: 22px; font-weight: 700; color: #0f172a; margin: 0 0 6px; }
  .meta { color: #64748b; margin-bottom: 24px; font-size: 12px; }
  .stats { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 120px; padding: 14px 18px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05); }
  .stat .label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: #64748b; letter-spacing: 0.04em; margin-bottom: 4px; }
  .stat .value { font-size: 24px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; font-size: 12px; }
  th, td { border-bottom: 1px solid #e2e8f0; padding: 10px 14px; text-align: left; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; text-transform: uppercase; font-size: 11px; color: #475569; letter-spacing: 0.04em; }
  tr:last-child td { border-bottom: none; }
  .findings-row td { background: #f8fafc; color: #475569; font-size: 11.5px; padding-left: 24px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  @media print { body { background: #fff; padding: 12px; } .stat, table { box-shadow: none; } }
</style>
</head>
<body>
  <h1>SecureMailScope — Cryptographic Security Posture Report</h1>
  <div class="meta">Generated ${esc(generatedAt)} ${meta.runId ? `· Run ${esc(meta.runId)}` : ''} · ${sessions.length} sessions</div>
  <div class="stats">
    <div class="stat"><div class="label">Total</div><div class="value">${sessions.length}</div></div>
    <div class="stat"><div class="label">Critical</div><div class="value" style="color:${SEV_HEX.critical}">${counts.critical || 0}</div></div>
    <div class="stat"><div class="label">High</div><div class="value" style="color:${SEV_HEX.high}">${counts.high || 0}</div></div>
    <div class="stat"><div class="label">Medium</div><div class="value" style="color:${SEV_HEX.medium}">${counts.medium || 0}</div></div>
    <div class="stat"><div class="label">Low</div><div class="value" style="color:${SEV_HEX.low}">${counts.low || 0}</div></div>
    <div class="stat"><div class="label">Anomalies</div><div class="value">${anomalies}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Session</th><th>Protocol</th><th>TLS</th><th>Cipher Suite</th>
        <th>PFS</th><th>Cert</th><th>Score</th><th>Severity</th><th>Anomaly</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportJson(sessions, filename = 'securemailscope-report.json') {
  download(filename, JSON.stringify(sessions, null, 2), 'application/json');
}

export function exportHtml(sessions, filename = 'securemailscope-report.html') {
  download(filename, buildHtmlReport(sessions), 'text/html');
}

export function exportPdfViaPrint(sessions) {
  const win = window.open('', '_blank');
  if (!win) return;
  win.document.write(buildHtmlReport(sessions));
  win.document.close();
  win.onload = () => win.print();
}
