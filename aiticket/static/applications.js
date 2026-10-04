document.addEventListener('input', event => {
  if (!event.target.matches('[data-check-search]')) return;
  const form = event.target.closest('.application-form');
  const query = event.target.value.toLowerCase();
  for (const option of form.querySelectorAll('[data-check-option]')) option.hidden = !option.textContent.toLowerCase().includes(query);
});
document.addEventListener('click', event => {
  const form = event.target.closest('.application-form');
  if (!form) return;
  if (event.target.closest('[data-add-dependency]')) {
    form.querySelector('[data-dependencies]').append(form.querySelector('template').content.cloneNode(true));
    event.target.dispatchEvent(new Event('input', {bubbles:true}));
  }
  if (event.target.closest('[data-remove-dependency]')) {
    event.target.dispatchEvent(new Event('input', {bubbles:true}));
    event.target.closest('.dependency-row').remove();
  }
});
