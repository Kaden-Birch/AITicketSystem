(() => {
  const media = matchMedia('(prefers-color-scheme: dark)');
  let choice = 'system';
  try { choice = localStorage.getItem('aiticket-theme') || 'system'; } catch (_) {}
  if (!['system', 'dark', 'light'].includes(choice)) choice = 'system';
  function apply() { document.documentElement.dataset.theme = choice === 'system' ? (media.matches ? 'dark' : 'light') : choice; }
  apply(); media.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    const select = document.getElementById('theme-choice');
    if (!select) return;
    select.value = choice;
    select.addEventListener('change', () => { choice = select.value; try { localStorage.setItem('aiticket-theme', choice); } catch (_) {} apply(); });
  });
})();
