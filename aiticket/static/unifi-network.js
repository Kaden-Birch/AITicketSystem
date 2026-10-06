(() => {
  const root=document.getElementById('unas-workspace'),dialog=document.getElementById('unet-drawer');if(!root||!dialog)return;
  const $=id=>document.getElementById(id),data=()=>JSON.parse($('unas-data').textContent);let selected=0,trigger=null;
  function render(){const ports=data().ports,p=ports[selected];if(!p){dialog.close();return} $('unet-title').textContent=p.name;$('unet-state').textContent=p.label;$('unet-state').className='unas-status '+p.state;$('unet-fields').replaceChildren();for(const [name,value] of p.fields){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;$('unet-fields').append(dt,dd)}$('unet-prev').disabled=selected===0;$('unet-next').disabled=selected===ports.length-1;}
  root.addEventListener('click',e=>{const port=e.target.closest('[data-port]');if(!port)return;selected=Number(port.dataset.port);trigger=port;render();dialog.showModal()});
  $('unet-close').onclick=()=>dialog.close();dialog.addEventListener('close',()=>trigger?.focus());$('unet-prev').onclick=()=>{selected--;render()};$('unet-next').onclick=()=>{selected++;render()};
  let latest=$('unas-data').textContent;new MutationObserver(()=>{const next=$('unas-data').textContent;if(next!==latest){latest=next;if(dialog.open)render()}}).observe(root,{childList:true,subtree:true,characterData:true});
})();
