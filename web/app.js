let receipts = [],
  filter = 'all';
const $ = (id) => document.getElementById(id);
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function renderReceipts() {
  const list = $('receipts-list');
  list.replaceChildren();
  const shown = receipts
    .filter((d) => filter === 'all' || d.payload.receipt_type === filter)
    .slice(0, 30);
  if (!shown.length) {
    list.append(
      el(
        'p',
        'No receipts in this view. Run ./bin/passport demo to exercise the trust chain.',
        'empty',
      ),
    );
    return;
  }
  for (const doc of shown) {
    const r = doc.payload,
      details = el('details'),
      summary = el('summary');
    summary.append(
      el('span', r.receipt_type, `badge ${r.receipt_type}`),
      el('span', r.code.replaceAll('_', ' ')),
      el('span', r.request_id, 'receipt-id'),
      el(
        'span',
        new Date(r.issued_at * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        'receipt-time',
      ),
    );
    const content = el('div', undefined, 'receipt-details'),
      trace = el('div', undefined, 'trace');
    for (const step of r.trace ?? []) trace.append(el('span', '✓ ' + step.replaceAll('_', ' ')));
    content.append(trace, el('pre', JSON.stringify(doc, null, 2)));
    details.append(summary, content);
    list.append(details);
  }
}
async function refresh() {
  try {
    const responses = await Promise.all([
      fetch('/v0/overview'),
      fetch('/v0/receipts'),
      fetch('/v0/globex-receipts'),
    ]);
    if (responses.some((r) => !r.ok)) throw Error('Service unavailable');
    const [data, authorizations, executions] = await Promise.all(responses.map((r) => r.json()));
    $('health').classList.remove('error');
    $('health').replaceChildren(
      el('span', undefined, 'dot'),
      document.createTextNode('Services connected'),
    );
    $('org-count').textContent = data.organizations.length;
    const agents = data.records.filter((r) => r.kind === 'agent');
    const active = agents.filter(
      (a) =>
        !a.revoked &&
        data.records.some(
          (k) =>
            k.kind === 'runtime_key' &&
            k.document.payload.agent_id === a.id &&
            !k.revoked &&
            k.document.payload.expires_at > Date.now() / 1000 &&
            data.records.some(
              (d) =>
                d.kind === 'delegation' &&
                !d.revoked &&
                d.id === k.document.payload.delegation_id &&
                d.document.payload.expires_at > Date.now() / 1000,
            ),
        ),
    );
    $('agent-count').textContent = active.length;
    $('execution-count').textContent = executions.filter(
      (r) => r.payload.receipt_type === 'execution',
    ).length;
    const table = $('agents-list');
    table.replaceChildren();
    for (const a of agents.slice(0, 12)) {
      const tr = el('tr'),
        name = el('td', undefined, 'agent-name');
      name.append(el('span', a.id));
      const key = data.records.find(
        (k) => k.kind === 'runtime_key' && k.document.payload.agent_id === a.id,
      );
      if (key) name.append(el('small', key.id));
      const delegated = data.records.find(
        (d) => d.kind === 'delegation' && d.document.payload.agent_id === a.id,
      );
      const valid =
        active.includes(a) &&
        delegated &&
        !delegated.revoked &&
        delegated.document.payload.expires_at > Date.now() / 1000;
      const status = el('td');
      status.append(el('span', valid ? 'Active' : 'Inactive', `badge ${valid ? '' : 'denial'}`));
      tr.append(
        name,
        el('td', a.org_id === 'acme' ? 'Acme Research' : a.org_id),
        el('td', delegated?.document.payload.actions.join(', ') ?? 'Pending'),
        status,
      );
      table.append(tr);
    }
    if (!agents.length) {
      const row = el('tr'),
        cell = el('td', 'No agents enrolled. Run ./bin/dev.', 'empty');
      cell.colSpan = 4;
      row.append(cell);
      table.append(row);
    }
    receipts = [...authorizations, ...executions].sort(
      (a, b) => b.payload.issued_at - a.payload.issued_at,
    );
    renderReceipts();
  } catch {
    $('health').textContent = 'Service unavailable';
    $('health').classList.add('error');
  }
}
$('refresh').addEventListener('click', refresh);
$('copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText('./bin/passport connect codex-local');
    $('copy').textContent = 'Copied ✓';
    setTimeout(() => ($('copy').textContent = 'Copy command ⧉'), 1800);
  } catch {
    $('copy').textContent = 'Select command to copy';
  }
});
for (const button of document.querySelectorAll('[data-filter]'))
  button.addEventListener('click', () => {
    filter = button.dataset.filter;
    for (const b of document.querySelectorAll('[data-filter]'))
      b.classList.toggle('active', b === button);
    renderReceipts();
  });
refresh();
setInterval(refresh, 15000);
