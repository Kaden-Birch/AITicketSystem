(() => {
  const type = document.getElementById('host-kind');
  if (type) {
    const update = () => {
      const nas = type.value === 'truenas';
      const fields = document.getElementById('nas-fields');
      fields.hidden = !nas; fields.disabled = !nas;
      document.getElementById('agent-help').hidden = nas;
    };
    type.addEventListener('change', update); update();
  }
  document.addEventListener('input', event => {
    if (!event.target.matches('[data-inventory-search]')) return;
    const area = event.target.closest('details,section');
    const value = event.target.value.trim().toLowerCase();
    area.querySelectorAll('[data-inventory-row]').forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(value); });
  });
})();
