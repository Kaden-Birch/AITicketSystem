(() => {
  document.querySelectorAll('[data-maintenance-form]').forEach(form => {
    const choice = form.querySelector('[data-schedule-choice]');
    const update = () => form.querySelectorAll('[data-schedule]').forEach(block => {
      const active = block.dataset.schedule === choice.value;
      block.hidden = !active;
      block.querySelectorAll('input,select').forEach(input => {
        input.disabled = !active;
        if (input.type === 'time' || input.type === 'datetime-local') input.required = active;
      });
    });
    choice.addEventListener('change', update);
    update();
  });
})();
