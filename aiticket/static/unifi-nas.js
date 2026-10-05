(() => {
  'use strict';
  const root=document.getElementById('unas-workspace');if(!root)return;
  const $=id=>document.getElementById(id);
  const data=()=>JSON.parse($('unas-data').textContent);
  function bars(){root.querySelectorAll('[data-fill]').forEach(el=>{el.style.width=Math.max(0,Math.min(100,Number(el.dataset.fill)||0))+'%'})}bars();
  let selected=0,trigger=null,index=0;
  const dialog=$('unas-drawer');
  function drive(){const disks=data().disks,d=disks[selected];if(!d)return; $('unas-drawer-title').textContent='Bay '+d.slot;$('unas-drive-status').textContent=d.state.charAt(0).toUpperCase()+d.state.slice(1);$('unas-drive-status').className='unas-status '+d.state;$('unas-drive-fields').replaceChildren();for(const [name,value] of [['Reported state',d.reported],...d.fields]){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;$('unas-drive-fields').append(dt,dd)}$('unas-prev').disabled=selected===0;$('unas-next').disabled=selected===disks.length-1;}
  root.addEventListener('click',e=>{const bay=e.target.closest('[data-drive]');if(!bay)return;selected=Number(bay.dataset.drive);trigger=bay;drive();dialog.showModal();});
  $('unas-close').onclick=()=>dialog.close();dialog.addEventListener('close',()=>trigger?.focus());dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close()}});
  $('unas-prev').onclick=()=>{selected--;drive()};$('unas-next').onclick=()=>{selected++;drive()};
  $('unas-range').onchange=e=>{const url=new URL(location.href);url.searchParams.set('window',e.target.value);location.assign(url)};
  // Exact retained samples, with no interpolation across missing readings.
  const ns='http://www.w3.org/2000/svg';let latest='';
  function chart(){const d=data();latest=$('unas-data').textContent;const samples=d.samples,max=Math.max(1,...samples.flatMap(p=>[p.read||0,p.write||0]));$('unas-lines').replaceChildren();for(const field of ['read','write']){let points=[];function flush(){if(!points.length)return;const el=document.createElementNS(ns,points.length===1?'circle':'polyline');if(points.length===1){el.setAttribute('cx',points[0][0]);el.setAttribute('cy',points[0][1]);el.setAttribute('fill',field==='read'?'var(--accent)':'var(--write)')}else el.setAttribute('points',points.map(p=>p.join(',')).join(' '));el.setAttribute('stroke',field==='read'?'var(--accent)':'var(--write)');$('unas-lines').append(el);points=[]}let prev=null;for(const p of samples){if(p[field]===null||(prev!==null&&p.at-prev>d.gap))flush();if(p[field]!==null)points.push([(p.at-d.start)/(d.end-d.start)*600,120-p[field]/max*110]);prev=p.at}flush()}
    $('unas-hit').setAttribute('aria-valuemax',Math.max(0,samples.length-1));index=Math.min(index,Math.max(0,samples.length-1));hide();}
  function hide(){$('unas-tip').hidden=true;$('unas-cursor').setAttribute('visibility','hidden')}
  function inspect(i){const d=data(),p=d.samples[i];if(!p)return;index=i;const width=$('unas-hit').clientWidth,x=(p.at-d.start)/(d.end-d.start);$('unas-tip').textContent=new Date(p.at).toLocaleString()+'\nRead: '+(p.read===null?'Not reported':p.read.toFixed(2)+' MB/s')+'\nWrite: '+(p.write===null?'Not reported':p.write.toFixed(2)+' MB/s');$('unas-tip').hidden=false;$('unas-tip').style.left=Math.max(0,Math.min(width-$('unas-tip').offsetWidth,x*width-110))+'px';$('unas-cursor').setAttribute('x1',x*600);$('unas-cursor').setAttribute('x2',x*600);$('unas-cursor').setAttribute('visibility','visible');$('unas-hit').setAttribute('aria-valuenow',i);$('unas-hit').setAttribute('aria-valuetext',$('unas-tip').textContent)}
  function pointer(e){const d=data(),r=e.currentTarget.getBoundingClientRect(),at=d.start+(e.clientX-r.left)/r.width*(d.end-d.start);let nearest=0;d.samples.forEach((p,i)=>{if(Math.abs(p.at-at)<Math.abs(d.samples[nearest].at-at))nearest=i});if(d.samples.length)inspect(nearest)}
  $('unas-hit').onpointermove=pointer;$('unas-hit').onpointerdown=pointer;$('unas-hit').onpointerleave=hide;$('unas-hit').onfocus=()=>inspect(index);$('unas-hit').onblur=hide;$('unas-hit').onkeydown=e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();inspect(e.key==='Home'?0:e.key==='End'?data().samples.length-1:Math.max(0,Math.min(data().samples.length-1,index+(e.key==='ArrowLeft'?-1:1))))}};chart();
  // The normal page refresher preserves an open drawer; redraw changed history afterward.
  new MutationObserver(()=>{bars();if($('unas-data').textContent!==latest){chart();if(dialog.open)drive()}}).observe(root,{childList:true,subtree:true,characterData:true});
})();
