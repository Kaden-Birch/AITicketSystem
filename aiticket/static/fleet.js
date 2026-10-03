(() => {
  const form = document.querySelector('[data-fleet-form]');
  if (!form) return;
  function update() {
    for (const panel of form.querySelectorAll('[data-fleet-kinds]')) {
      const active = panel.dataset.fleetKinds.split(' ').includes(form.elements.kind.value);
      panel.hidden = !active;
      for (const field of panel.querySelectorAll('input,select,textarea')) field.disabled = !active;
    }
  }
  form.elements.kind.addEventListener('change', update);
  form.querySelector('[data-fleet-group]').addEventListener('change', event => {
    const group = event.target.value;
    if (!group) return;
    for (const field of form.querySelectorAll('[name="targets"]')) field.checked = group === 'all' || field.dataset.group === group;
  });
  function selectionCount() {
    const count = form.querySelectorAll('[name="targets"]:checked').length;
    const output = form.querySelector('[data-fleet-count]');
    if (output) output.textContent = count + ' selected';
  }
  form.addEventListener('change', selectionCount);
  form.addEventListener('input', () => {
    const output = form.querySelector('[data-fleet-draft]');
    if (output) output.textContent = 'Draft · not submitted';
  });
  const preset = JSON.parse(form.querySelector('[data-fleet-preset]').value);
  for (const [name, value] of Object.entries(preset)) if (form.elements[name]) form.elements[name].value = value;
  update();
  selectionCount();
})();
