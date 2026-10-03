/* Optional endpoint rows share the cluster credential; no separate node setup. */
(() => {
  let next = 0;
  document.addEventListener('click', event => {
    const add = event.target.closest('[data-add-endpoint]');
    if (add) {
      const rows = add.closest('[data-proxmox-endpoints]').querySelector('[data-endpoint-rows]');
      const row = document.createElement('div'); row.className = 'proxmox-endpoint-row';
      const label = document.createElement('label'); label.textContent = 'Additional IP address or HTTPS URL';
      const input = document.createElement('input'); input.name = 'additional_url'; input.id = 'proxmox-endpoint-' + next++;
      input.placeholder = '192.0.2.11 or https://pve2.example.com:8006'; label.htmlFor = input.id; label.append(input);
      const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove';
      remove.dataset.removeEndpoint = ''; remove.setAttribute('aria-label', 'Remove additional endpoint');
      row.append(label, remove); rows.append(row); input.dispatchEvent(new Event('input', {bubbles:true})); input.focus();
    }
    const remove = event.target.closest('[data-remove-endpoint]');
    if (remove) { const wrapper = remove.closest('[data-proxmox-endpoints]'); remove.closest('.proxmox-endpoint-row').remove(); wrapper.dispatchEvent(new Event('input', {bubbles:true})); wrapper.querySelector('[data-add-endpoint]').focus(); }
  });
  const selector = document.querySelector('select[name="cluster_id"]');
  function shared() {
    if (!selector) return;
    for (const name of ['token_id','token_secret','ca','cluster_name']) {
      const field = selector.form.elements[name];
      field.disabled = !!selector.value; field.closest('label').hidden = !!selector.value;
    }
  }
  selector?.addEventListener('change', shared); shared();
})();
