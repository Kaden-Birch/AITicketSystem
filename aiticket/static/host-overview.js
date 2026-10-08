(() => {
  const page=document.querySelector('.host-design'); if(!page)return;
  const drawer=document.getElementById('host-inventory-drawer'),content=document.getElementById('host-drawer-content'),search=document.getElementById('host-drawer-search'),sort=document.getElementById('host-drawer-sort'),back=document.getElementById('host-drawer-back'),tools=document.getElementById('host-drawer-search-label');
  let list='',trigger=null,cursor=119,inspecting=false;
  const titles={processes:'All running processes',checks:'All monitoring checks'};
  function fills(){page.querySelectorAll('[data-host-fill]').forEach(el=>{el.style.width=Math.min(100,Math.max(0,Number(el.dataset.hostFill)))+'%';});}
  function containers(){
    const q=document.getElementById('container-search').value.toLowerCase(),state=document.getElementById('container-filter').value;
    let n=0;
    document.querySelectorAll('#container-rows>.inventory-row').forEach(row=>{
      row.hidden=!(row.querySelector('.identity').textContent.toLowerCase().includes(q)&&(state==='all'||state===row.dataset.state||state==='stopped'&&row.dataset.state!=='running'||state==='attention'&&row.dataset.health==='unhealthy'));
      if(!row.hidden)n++;
    });
    document.getElementById('containers-empty').hidden=n>0;
  }
  function filter(){
    let visible=0;
    const rows=[...content.querySelectorAll(':scope > .inventory-row,:scope > .check')];
    rows.sort((a,b)=>sort.value==='name'?(a.dataset.name||'').localeCompare(b.dataset.name||''):Number(b.dataset[sort.value]??-1)-Number(a.dataset[sort.value]??-1));
    rows.forEach(row=>{row.hidden=!row.textContent.toLowerCase().includes(search.value.toLowerCase());if(!row.hidden)visible++;content.append(row);});
    document.getElementById('host-drawer-empty').hidden=visible>0;
  }
  function populate(){
    content.replaceChildren(document.getElementById('host-list-'+list).content.cloneNode(true));
    document.getElementById('host-drawer-title').textContent=titles[list];
    document.getElementById('host-drawer-kicker').textContent=list==='processes'?'PROCESS INVENTORY':'HOST CHECKS';
    tools.hidden=false;sort.hidden=list!=='processes';back.hidden=true;filter();fills();
  }
  function open(button){if(!drawer.open){trigger=button;drawer.showModal();}document.querySelector('.drawer-body').scrollTop=0;}
  page.addEventListener('click',event=>{
    const button=event.target.closest('[data-host-list]');
    if(button){list=button.dataset.hostList;populate();open(button);search.focus();}
    const detail=event.target.closest('[data-host-details]');
    if(detail){
      const row=detail.closest('[data-host-entry]'),inList=drawer.contains(detail);
      if(!inList)list='';
      tools.hidden=true;back.hidden=!inList;
      document.getElementById('host-drawer-title').textContent=row.dataset.name;
      document.getElementById('host-drawer-kicker').textContent=row.dataset.state?'DOCKER CONTAINER':'PROCESS SNAPSHOT';
      const state=row.querySelector('.state').cloneNode(true),body=row.querySelector('.entry-details').cloneNode(true);body.open=true;
      content.replaceChildren(state,body);document.getElementById('host-drawer-empty').hidden=true;fills();open(detail);
    }
    const check=event.target.closest('[data-host-check]');
    if(check&&!drawer.contains(check)){
      list='';tools.hidden=true;back.hidden=true;document.getElementById('host-drawer-empty').hidden=true;
      document.getElementById('host-drawer-title').textContent=check.querySelector('strong').textContent;
      document.getElementById('host-drawer-kicker').textContent='MONITORING CHECK';
      const copy=check.cloneNode(true);copy.removeAttribute('data-host-check');copy.querySelector('details').open=true;
      content.replaceChildren(copy);open(check);
    }
    const extra=event.target.closest('[data-host-extra]');
    if(extra){list='';tools.hidden=true;back.hidden=true;document.getElementById('host-drawer-empty').hidden=true;
      const kind=extra.dataset.hostExtra;
      document.getElementById('host-drawer-title').textContent={storage:'Storage & capacity',access:'Network & access',operations:'Host operations'}[kind];
      document.getElementById('host-drawer-kicker').textContent='HOST DETAILS';
      content.replaceChildren(document.getElementById('host-extra-'+kind).content.cloneNode(true));fills();open(extra);
    }
    if(event.target.closest('[data-host-close]'))drawer.close();
  });
  back.addEventListener('click',()=>{populate();search.focus();});search.addEventListener('input',filter);sort.addEventListener('change',filter);
  drawer.addEventListener('close',()=>{trigger?.focus();});
  drawer.addEventListener('click',event=>{if(event.target===drawer&&event.clientX<drawer.getBoundingClientRect().left)drawer.close();});
  page.addEventListener('input',event=>{if(event.target.id==='container-search')containers();});
  page.addEventListener('change',async event=>{
    if(event.target.id==='container-filter')containers();
    if(event.target.matches('[data-container-window]')){
      const select=event.target,section=select.closest('[data-container-history]'),url=new URL(location.href);
      url.searchParams.set('window',select.value);select.disabled=true;
      try{
        const response=await fetch(url,{credentials:'same-origin'});if(!response.ok)throw new Error('History request failed');
        const documentCopy=new DOMParser().parseFromString(await response.text(),'text/html');
        const row=[...documentCopy.querySelectorAll('#container-rows>[data-host-entry]')].find(item=>item.dataset.liveKey==='inventory-docker-'+select.dataset.containerTarget);
        const fresh=row?.querySelector('[data-container-history]');if(!fresh)throw new Error('Container no longer reported');
        if(section.isConnected){section.replaceChildren(...fresh.childNodes);fills();}
      }catch(error){let notice=section.querySelector('[data-history-error]');if(!notice){notice=document.createElement('p');notice.className='caption';notice.dataset.historyError='';section.append(notice);}notice.textContent='History could not be loaded. Retry by selecting a time range.';}
      finally{select.disabled=false;}
    }
    if(event.target.id==='host-history-window'){const url=new URL(location.href);url.searchParams.set('window',event.target.value);location.assign(url);}
  });
  function inspect(index,scope=page.querySelector('#host-charts')){
    cursor=Math.min(119,Math.max(0,index));if(scope.id==='host-charts')inspecting=true;
    const cards=[...scope.querySelectorAll('[data-host-chart]')];
    const reference=cards.map(card=>JSON.parse(card.dataset.chartRecord)).find(chart=>chart.samples?.length);
    cards.forEach(card=>{
      const chart=JSON.parse(card.dataset.chartRecord),sample=chart.samples[cursor],at=sample?.at??reference?.samples[cursor]?.at;
      const x=38+(cursor+.5)/120*554,line=card.querySelector('[data-chart-cursor]');
      line.hidden=false;line.removeAttribute('hidden');line.setAttribute('x1',x);line.setAttribute('x2',x);
      const marker=card.querySelector('[data-chart-point]');marker.setAttribute('visibility',sample?.value==null?'hidden':'visible');if(sample?.value!=null){marker.setAttribute('cx',x);marker.setAttribute('cy',126-Math.min(1,Math.max(0,sample.value/chart.ceiling))*112);}
      card.querySelector('[data-chart-value]').textContent=sample?.value==null?'—':Number(sample.value.toFixed(2))+chart.unit;
      card.querySelector('[data-chart-time]').textContent=(at?new Date(at*1000).toLocaleString()+' · ':'')+(sample?.value==null?'No reading collected':Number(sample.value.toFixed(2))+chart.unit+' · interval average');
    });
  }
  function point(event){const svg=event.target.closest('[data-host-chart] svg');if(!svg)return;const box=svg.getBoundingClientRect();inspect(Math.floor(((event.clientX-box.left)/box.width*600-38)/554*120),svg.closest('.charts'));}
  page.addEventListener('pointermove',point);page.addEventListener('click',point);
  page.addEventListener('keydown',event=>{
    if(event.target.matches('[data-host-check]')&&['Enter',' '].includes(event.key)){event.preventDefault();event.target.click();return;}
    if(!event.target.matches('[data-host-chart] svg'))return;
    if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();inspect(event.key==='Home'?0:event.key==='End'?119:cursor+(event.key==='ArrowLeft'?-1:1),event.target.closest('.charts'));}
  });
  document.addEventListener('aiticket:live-updated',()=>{fills();containers();if(inspecting)inspect(cursor);});
  fills();containers();
})();
