/* Update server-rendered information while preserving active edits and disclosures. */
(() => {
  'use strict';
  const paths = [/^\/$/, /^\/hosts(?:\/[^/]+)?$/, /^\/incidents\/[^/]+$/, /^\/proxmox\/resources\/[^/]+$/, /^\/(history|queue|audit|hermes|proxmox|unifi|resources)$/];
  if (!paths.some(pattern => pattern.test(location.pathname))) return;
  const dirty = new WeakSet();
  document.addEventListener('input', event => { if (event.target.form) dirty.add(event.target.form); });
  document.addEventListener('change', event => { if (event.target.form) dirty.add(event.target.form); });
  let stopped = false;
  let controller;
  document.addEventListener('submit', () => { stopped = true; controller?.abort(); });
  window.addEventListener('pagehide', () => { stopped = true; controller?.abort(); });
  const status = document.createElement('small');
  status.className = 'live-status';
  status.setAttribute('role', 'status');
  status.textContent = 'Live updates enabled';
  document.querySelector('header')?.append(status);
  function key(node) {
    if (node.nodeType !== Node.ELEMENT_NODE) return null;
    if (node.dataset.liveKey) return node.dataset.liveKey;
    // Form controls named id shadow HTMLFormElement.id; read the attribute.
    const identifier = node.getAttribute('id');
    if (identifier) return identifier;
    if (node.matches('form')) return 'form:' + (node.getAttribute('action') || '') + ':' + ['section', 'operation', 'machine_id', 'agent_id', 'check_id', 'object_id', 'connection_id', 'id'].map(name => node.querySelector('[name="' + name + '"]')?.value || '').join(':');
    return null;
  }
  function edited(node) {
    return node.contains?.(document.activeElement) || (node.nodeType === Node.ELEMENT_NODE &&
      ((node.matches('form') && dirty.has(node)) || [...node.querySelectorAll('form')].some(form => dirty.has(form))));
  }
  function sync(current, next) {
    if (current.nodeType !== next.nodeType || current.nodeName !== next.nodeName) {
      if (!edited(current)) current.replaceWith(next.cloneNode(true));
      return;
    }
    if (current.nodeType === Node.TEXT_NODE) {
      if (current.nodeValue !== next.nodeValue) current.nodeValue = next.nodeValue;
      return;
    }
    if (current.nodeType !== Node.ELEMENT_NODE) return;
    if (current.matches('form') && (dirty.has(current) || current.contains(document.activeElement))) return;
    const open = current.matches('details') ? current.open : null;
    for (const attr of [...current.attributes]) if (!next.hasAttribute(attr.name)) current.removeAttribute(attr.name);
    for (const attr of [...next.attributes]) if (current.getAttribute(attr.name) !== attr.value) current.setAttribute(attr.name, attr.value);
    if (open !== null) current.open = open;
    const keyed = new Map([...current.childNodes].map(child => [key(child), child]).filter(([name]) => name));
    for (let index = 0; index < next.childNodes.length; index++) {
      const incoming = next.childNodes[index];
      let existing = current.childNodes[index];
      if (key(incoming)) {
        const match = keyed.get(key(incoming));
        if (match && match !== existing) { current.insertBefore(match, existing || null); existing = match; }
      }
      if (existing && key(incoming) && key(existing) && key(incoming) !== key(existing)) { current.insertBefore(incoming.cloneNode(true), existing); }
      else if (!existing) current.append(incoming.cloneNode(true));
      else sync(existing, incoming);
    }
    while (current.childNodes.length > next.childNodes.length) {
      const extra = current.lastChild;
      if (edited(extra)) break;
      extra.remove();
    }
  }
  async function refresh() {
    if (stopped || document.hidden) return;
    controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(location.href, {credentials: 'same-origin', cache: 'no-store', headers: {'X-AITicket-Live': '1'}, signal: controller.signal});
      if (response.redirected && new URL(response.url).pathname === '/login') {
        stopped = true; status.textContent = 'Session expired — sign in to resume updates'; return;
      }
      if (!response.ok) throw new Error('Update unavailable');
      const page = new DOMParser().parseFromString(await response.text(), 'text/html');
      const current = document.querySelector('main');
      const next = page.querySelector('main');
      if (current && next) sync(current, next);
      status.textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (error) {
      if (!stopped) status.textContent = 'Updates unavailable — retrying';
    } finally { clearTimeout(timeout); }
  }
  // Sequential requests prevent slow responses from overwriting newer content.
  async function loop() { await refresh(); if (!stopped) setTimeout(loop, 5000); }
  setTimeout(loop, 5000);
})();
