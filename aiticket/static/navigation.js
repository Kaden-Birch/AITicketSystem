(() => {
  const menu = document.getElementById('site-menu'), toggle = document.getElementById('menu-toggle');
  if (!menu) return;
  const shade = document.getElementById('menu-shade');
  function showMenu(open) {
    menu.classList.toggle('open', open); menu.inert = !open;
    toggle.setAttribute('aria-expanded', String(open)); shade.hidden = !open;
  }
  toggle.addEventListener('click', () => showMenu(!menu.classList.contains('open')));
  document.getElementById('menu-close').addEventListener('click', () => { showMenu(false); toggle.focus(); });
  shade.addEventListener('click', () => showMenu(false));
  document.getElementById('menu-edge').addEventListener('pointerenter', e => { if (e.pointerType === 'mouse') showMenu(true); });
  document.addEventListener('pointermove', e => {
    if (e.pointerType === 'mouse' && menu.classList.contains('open') && e.clientX > menu.getBoundingClientRect().right + 24 && !menu.contains(document.activeElement)) showMenu(false);
  });
  const dialog = document.getElementById('command-palette'), input = document.getElementById('global-search'), results = document.getElementById('search-results'), status = document.getElementById('search-status');
  let selected = -1, controller, timer;
  function select(index) {
    const links = [...results.querySelectorAll('a')];
    selected = links.length ? (index + links.length) % links.length : -1;
    links.forEach((link, i) => { link.classList.toggle('selected', i === selected); if (i === selected) link.scrollIntoView({block:'nearest'}); });
  }
  async function search() {
    controller?.abort(); controller = new AbortController(); selected = -1;
    try {
      status.textContent = 'Searching…';
      const response = await fetch('/search?q=' + encodeURIComponent(input.value), {signal:controller.signal, headers:{Accept:'application/json'}});
      if (!response.ok || response.redirected) throw new Error('Search unavailable');
      const payload = await response.json(); results.replaceChildren();
      for (const result of payload.results) {
        const link = document.createElement('a'); link.href = result.url;
        const title = document.createElement('strong'); title.textContent = result.label;
        const kind = document.createElement('small'); kind.textContent = result.kind;
        link.append(title, kind); results.append(link);
      }
      status.textContent = payload.results.length ? payload.results.length + ' results' : 'No matching results';
    } catch (error) { if (error.name !== 'AbortError') status.textContent = 'Search unavailable — try again'; }
  }
  function openSearch() { showMenu(false); dialog.showModal(); input.focus(); search(); }
  document.getElementById('search-toggle').addEventListener('click', openSearch);
  document.getElementById('search-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { controller?.abort(); clearTimeout(timer); });
  input.addEventListener('input', () => { controller?.abort(); clearTimeout(timer); timer = setTimeout(search, 180); });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); select(selected + (e.key === 'ArrowDown' ? 1 : -1)); }
    if (e.key === 'Enter') { e.preventDefault(); const links = results.querySelectorAll('a'); const link = links[selected < 0 ? 0 : selected]; if (link) location.assign(link.href); }
  });
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (!dialog.open) openSearch(); }
    if (e.key === 'Escape' && menu.classList.contains('open')) { showMenu(false); toggle.focus(); }
  });
  const check = location.hash.startsWith('#check-') ? document.getElementById(location.hash.slice(1)) : null;
  if (check?.matches('details')) check.open = true;
})();
