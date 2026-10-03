(() => {
  document.querySelectorAll('[data-health-card]').forEach(card => {
    const value = card.querySelector('[name=threshold]'), recovery = card.querySelector('[name=recovery]'), slider = card.querySelector('[type=range]'), enabled = card.querySelector('[name=enabled]');
    const unit = () => card.querySelector('[name=unit]:checked')?.value || card.querySelector('[name=unit]').value;
    function parse(text) {
      const match = text.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*(GB|MB|TB|%)?$/i);
      if (!match || (unit() === 'percent' && match[2] && match[2] !== '%') || (unit() === 'bytes' && match[2] === '%')) return null;
      const amount = Number(match[1]) * (unit() === 'bytes' ? ({GB:1,MB:0.001,TB:1000}[match[2]?.toUpperCase() || 'GB']) : 1);
      return Number.isFinite(amount) ? amount : null;
    }
    function updateRange() {
      const number = parse(value.value);
      slider.max = unit() === 'percent' ? 100 : Math.max(1000, number || 0, parse(recovery.value) || 0) * 1.2;
      slider.step = unit() === 'percent' ? 0.1 : 1;
      if (number !== null) slider.value = number;
      const label = unit() === 'percent' ? '%' : 'GB free';
      card.querySelector('[data-unit-label]').textContent = label; card.querySelector('[data-recovery-unit]').textContent = label;
    }
    function adjustRecovery() {
      const threshold = parse(value.value), current = parse(recovery.value);
      if (threshold === null || current === null) return;
      const below = card.dataset.direction === 'below';
      if (below ? current <= threshold : current >= threshold) {
        const gap = unit() === 'percent' ? 5 : Math.max(1, threshold * .1);
        recovery.value = Number((below ? Math.min(unit() === 'percent' ? 100 : 1e9, threshold + gap) : Math.max(0, threshold - gap)).toFixed(9));
      }
    }
    slider.addEventListener('input', () => { value.value = slider.value; adjustRecovery(); });
    [value,recovery].forEach(input => input.addEventListener('change', () => {
      const number = parse(input.value);
      input.setCustomValidity(number === null ? 'Enter a number, or free space in GB, MB or TB.' : '');
      if (number !== null) input.value = Number(number.toFixed(9));
      if (input === value) adjustRecovery();
      updateRange();
    }));
    [value,recovery].forEach(input => input.addEventListener('input', () => input.setCustomValidity('')));
    card.querySelectorAll('[name=unit][type=radio]').forEach(radio => radio.addEventListener('change', () => {
      // Units are separate thresholds; never interpret 15 percent as 15 bytes.
      const below = card.dataset.direction === 'below';
      value.value = unit() === 'bytes' ? 50 : 15; recovery.value = unit() === 'bytes' ? 60 : below ? 20 : 10;
      value.setCustomValidity(''); recovery.setCustomValidity(''); updateRange();
    }));
    enabled.addEventListener('change', () => card.classList.toggle('off', !enabled.checked || card.dataset.paused === '1'));
    updateRange();
  });
})();
