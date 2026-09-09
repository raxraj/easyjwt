import { parseJwt, pretty, lint, humanTime, verifyJwt, signJwt } from './jwt.js';

const $ = selector => document.querySelector(selector);
const tokenInput = $('#token');
const state = { parsed: null };

function setStatus(message, kind = '') { const el = $('#action-status'); el.textContent = message; el.className = `status ${kind}`; }
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c])); }
function renderTimes(payload) {
  const rows = ['exp', 'iat', 'nbf'].map(key => {
    const value = humanTime(payload[key]);
    return value ? `<article><strong>${key}</strong><span>${escapeHtml(String(payload[key]))}</span><small>${escapeHtml(value.local)} · ${escapeHtml(value.utc)}<br>${escapeHtml(value.relative)}</small></article>` : '';
  }).join('');
  $('#times').innerHTML = rows || '<p class="muted">No standard timestamp claims found.</p>';
}
function renderFindings(header, payload) {
  const findings = lint(header, payload);
  $('#findings').innerHTML = findings.map(item => `<article class="finding ${item.severity}"><b>${escapeHtml(item.severity)}</b><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p></div></article>`).join('');
}
function render(parsed) {
  state.parsed = parsed;
  $('#header-output').textContent = pretty(parsed.header);
  $('#payload-output').textContent = pretty(parsed.payload);
  $('#signature-output').textContent = parsed.signature || '(empty signature)';
  $('#payload-editor').value = pretty(parsed.payload);
  $('#header-editor').value = pretty(parsed.header);
  $('#alg-badge').textContent = parsed.header.alg || 'no alg';
  renderTimes(parsed.payload); renderFindings(parsed.header, parsed.payload);
  $('#results').hidden = false; $('#jwe-note').hidden = true;
  setStatus('Decoded locally. Nothing was sent anywhere.', 'success');
}
function decode() {
  try {
    const parsed = parseJwt(tokenInput.value);
    if (parsed.type === 'JWE') { $('#results').hidden = true; $('#jwe-note').hidden = false; setStatus('This is a five-part encrypted JWE, not a signed JWS.', 'warning'); return; }
    render(parsed);
  } catch (error) { state.parsed = null; $('#results').hidden = true; setStatus(error.message, 'error'); }
}
async function copy(value, label) { try { await navigator.clipboard.writeText(value); setStatus(`${label} copied to clipboard.`, 'success'); } catch { setStatus('Clipboard access was unavailable. Select and copy manually.', 'warning'); } }
async function verify() {
  if (!state.parsed) return setStatus('Decode a JWT first.', 'warning');
  try { const valid = await verifyJwt(state.parsed, $('#key-input').value); setStatus(valid ? 'Signature verified locally.' : 'Signature does not match this key.', valid ? 'success' : 'error'); }
  catch (error) { setStatus(`Verification failed: ${error.message}`, 'error'); }
}
async function regenerate() {
  if (!$('#local-warning').checked) return setStatus('Acknowledge the local-test warning before signing.', 'warning');
  try {
    const header = JSON.parse($('#header-editor').value), payload = JSON.parse($('#payload-editor').value);
    if (header.alg === 'none') throw new Error('Refusing to generate an unsigned token.');
    const token = await signJwt(header, payload, $('#key-input').value);
    tokenInput.value = token; render(parseJwt(token)); setStatus('Local test token generated. It was not stored or sent.', 'success');
  } catch (error) { setStatus(`Could not sign: ${error.message}`, 'error'); }
}
function reset() { tokenInput.value = ''; $('#key-input').value = ''; $('#header-editor').value = ''; $('#payload-editor').value = ''; $('#results').hidden = true; state.parsed = null; setStatus('Cleared token and key material from this page.', ''); }
function isolation() {
  const sw = navigator.serviceWorker?.controller ? 'Service worker active' : 'Service worker starting';
  $('#isolation').textContent = `${sw} · outbound connections blocked`;
}
$('#decode').addEventListener('click', decode); tokenInput.addEventListener('input', () => { if (tokenInput.value.trim().split('.').length === 3) decode(); });
$('#verify').addEventListener('click', verify); $('#regenerate').addEventListener('click', regenerate); $('#reset').addEventListener('click', reset);
document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', () => copy($(button.dataset.copy).textContent, button.textContent)));
if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').then(isolation).catch(() => { $('#isolation').textContent = 'CSP isolation active · service worker unavailable'; }); else isolation();
setInterval(() => { if (state.parsed) renderTimes(state.parsed.payload); }, 30000);
