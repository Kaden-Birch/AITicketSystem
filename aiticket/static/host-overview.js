(() => {
  function fills() {document.querySelectorAll('[data-host-fill]').forEach(el => {el.style.width=Math.min(100,Math.max(0,Number(el.dataset.hostFill)))+'%';});}
  fills();
  document.addEventListener('change',event => {if(event.target.id==='host-history-window'){const url=new URL(location.href);url.searchParams.set('window',event.target.value);location.assign(url);}});
  const drawer = document.getElementById('host-inventory-drawer');
  if (!drawer) return;
  const content = document.getElementById('host-drawer-content'), search = document.getElementById('host-drawer-search');
  let list = '', trigger = null, cursor = 119, detail = false, inspecting = false;
  const back = document.getElementById('host-drawer-back'), searchLabel = document.getElementById('host-drawer-search-label');
  function listMode() { detail=false; back.hidden=true; searchLabel.hidden=false; }
  function filter() {
    let visible = 0;
    content.querySelectorAll(':scope > article,:scope > details').forEach(row => {
      row.hidden = !row.textContent.toLowerCase().includes(search.value.toLowerCase());
      if (!row.hidden) visible++;
    });
    document.getElementById('host-drawer-empty').hidden = visible > 0;
  }
  function populate() {
    const template = document.getElementById('host-list-' + list);
    if (!template) return;
    content.replaceChildren(template.content.cloneNode(true)); fills(); filter();
  }
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-host-list]');
    if (button) {
      list = button.dataset.hostList; trigger = button; search.value = ''; listMode();
      document.getElementById('host-drawer-title').textContent = {checks:'All checks',containers:'All Docker containers',processes:'All processes'}[list];
      populate(); if (!drawer.open) drawer.showModal(); search.focus();
    }
    const details = event.target.closest('[data-host-details]');
    if (details) {
      if (!drawer.open) {trigger=details; list=''; search.value='';}
      detail=true; back.hidden=!list; searchLabel.hidden=true;
      const row=details.closest('[data-host-entry]').cloneNode(true);
      row.querySelector('details').open=true;
      document.getElementById('host-drawer-title').textContent=row.querySelector('strong').textContent;
      content.replaceChildren(row); fills(); document.getElementById('host-drawer-empty').hidden=true;
      if (!drawer.open) drawer.showModal();
    }
    if (event.target.closest('[data-host-close]')) drawer.close();
  });
  back.addEventListener('click', () => {listMode(); document.getElementById('host-drawer-title').textContent={checks:'All checks',containers:'All Docker containers',processes:'All processes'}[list]; populate(); search.focus();});
  search.addEventListener('input', filter);
  drawer.addEventListener('close', () => trigger?.focus());
  function inspect(index) {
    inspecting = true;
    cursor = Math.min(119, Math.max(0,index));
    const charts = JSON.parse(document.getElementById('host-chart-data').textContent);
    document.querySelectorAll('[data-host-chart]').forEach(card => {
      const chart = charts.find(c => c.key === card.dataset.hostChart), sample = chart?.samples[cursor];
      if (!sample) return;
      const line = card.querySelector('[data-chart-cursor]'), x = 35 + (cursor + .5) / 120 * 530;
      line.removeAttribute('hidden'); line.setAttribute('x1', x); line.setAttribute('x2', x);
      card.querySelector('[data-chart-value]').textContent = sample.value === null ? 'Unavailable' : Number(sample.value.toFixed(2)) + chart.unit;
      card.querySelector('[data-chart-time]').textContent = new Date(sample.at * 1000).toLocaleString() + ' · interval average';
    });
  }
  document.addEventListener('pointermove', event => {
    const svg = event.target.closest('[data-host-chart] svg'); if (!svg) return;
    const box = svg.getBoundingClientRect(), x = (event.clientX-box.left)/box.width*600;
    inspect(Math.floor((x-35)/530*120));
  });
  document.addEventListener('keydown', event => {
    if (!event.target.matches('[data-host-chart] svg')) return;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {event.preventDefault(); inspect(cursor+(event.key==='ArrowLeft'?-1:1));}
  });
  document.addEventListener('aiticket:live-updated', () => {
    fills();
    // Keep an open panel stable while people inspect evidence or prepare an action.
    if (inspecting) inspect(cursor);
  });
})();
