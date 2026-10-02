/* Show and submit only configuration belonging to the selected check type. */
(() => {
  function update(form) {
    const kind = form.elements.kind.value;
    for (const panel of form.querySelectorAll('[data-check-kinds]')) {
      const active = panel.dataset.checkKinds.split(' ').includes(kind);
      panel.hidden = !active;
      for (const field of panel.querySelectorAll('input,select,textarea')) field.disabled = !active;
    }
    const target = form.elements.target;
    form.querySelector('[data-target-label]').textContent = kind === 'smb' ? 'Mounted SMB directory' : 'Process name or systemd service';
    target.placeholder = kind === 'smb' ? '/mnt/photos' : 'immich.service';
    form.querySelector('[data-url-label]').textContent = kind === 'proxmox' ? 'HTTPS API URL' : 'URL';
    form.elements.url.placeholder = kind === 'proxmox' ? 'https://10.0.0.10:8006' : 'http://10.0.0.10:8080/health';
    const interval = form.elements.interval;
    interval.min = kind === 'ping' ? '1' : ['process', 'smb'].includes(kind) ? '20' : '10';
    if (interval.value && Number(interval.value) < Number(interval.min)) interval.value = interval.min;
  }
  document.querySelectorAll('[data-check-form]').forEach(update);
  document.addEventListener('change', event => {
    if (event.target.name === 'kind' && event.target.form?.matches('[data-check-form]')) update(event.target.form);
  });
})();
