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
  body { font-family: 'IBM Plex Mono', ui-monospace, monospace; background: #fff; color: #111; margin: 0; padding: 32px; font-size: 12px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .meta { color: #555; margin-bottom: 20px; font-size: 11px; }
  .stats { display: flex; gap: 0; border: 1px solid #ccc; margin-bottom: 24px; }
  .stat { flex: 1; padding: 10px 14px; border-right: 1px solid #ccc; }
  .stat:last-child { border-right: none; }
  .stat .label { font-size: 9px; text-transform: uppercase; color: #777; letter-spacing: 0.04em; }
  .stat .value { font-size: 18px; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; }
  th, td { border: 1px solid #ddd; padding: 5px 7px; text-align: left; vertical-align: top; }
  th { background: #f4f4f4; text-transform: uppercase; font-size: 9px; letter-spacing: 0.03em; }
  .findings-row td { background: #fafafa; color: #444; font-size: 10.5px; }
  .badge { padding: 1px 6px; border-radius: 2px; font-size: 10px; }
  @media print { body { padding: 12px; } }
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
