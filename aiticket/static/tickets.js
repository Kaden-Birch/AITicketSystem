(() => {
  const format = seconds => { seconds = Math.max(0, Math.floor(seconds)); return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m ${seconds % 60}s`; };
  const seen = new WeakMap();
  function elapsed(node) {
    const stamp = node.dataset.serverNow;
    let value = seen.get(node);
    if (!value || value.stamp !== stamp) { value = {stamp, at: performance.now()}; seen.set(node, value); }
    return (performance.now() - value.at) / 1000;
  }
  function clocks() {
    document.querySelectorAll('[data-seconds]').forEach(node => { if (!node.dataset.clockStart) node.textContent = format(Number(node.dataset.seconds)); });
    document.querySelectorAll('[data-clock-start]').forEach(node => { node.textContent = format(Number(node.dataset.serverNow) - Number(node.dataset.clockStart) + elapsed(node)); });
    document.querySelectorAll('[data-work-total]').forEach(node => { const active = document.querySelector(`[data-clock-actor="${node.dataset.workTotal}"]`); node.textContent = format(Number(node.dataset.baseSeconds) + (active ? elapsed(node) : 0)); });
  }
  clocks(); setInterval(clocks, 1000);
  const select = document.getElementById('ticket-machine');
  function preview() {
    if (!select) return;
    document.querySelectorAll('[data-machine-preview]').forEach(node => { node.hidden = node.dataset.machinePreview !== select.value; });
    document.getElementById('machine-placeholder').hidden = !!select.value;
  }
  select?.addEventListener('change', preview); preview();
  document.getElementById('machine-search')?.addEventListener('input', event => {
    const query = event.target.value.toLowerCase();
    for (const option of select.options) { const node = [...document.querySelectorAll('[data-machine-preview]')].find(node => node.dataset.machinePreview === option.value); option.hidden = !!option.value && !(node?.dataset.search || option.text).toLowerCase().includes(query); }
  });
})();
