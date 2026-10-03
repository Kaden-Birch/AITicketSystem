"""Bounded, optional read-only interface inventory; failures never stop heartbeats."""
import json
import re
import subprocess
from pathlib import Path


def command(args):
    try:
        with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as process:
            try:
                output=process.communicate(timeout=2)[0]
            except subprocess.TimeoutExpired:
                process.kill();process.communicate();return None
            return output.decode() if process.returncode==0 and len(output)<=262144 else None
    except (OSError,ValueError):return None


def read(path):
    try:return path.read_text().strip()[:200]
    except OSError:return ''


def neighbors(data):
    output=[]
    interfaces=data.get('lldp',{}).get('interface',{})
    if isinstance(interfaces,dict):interfaces=[interfaces]
    if not isinstance(interfaces,list):return output
    for item in interfaces[:64]:
        if not isinstance(item,dict):continue
        for name,details in item.items():
            if not isinstance(details,dict):continue
            chassis=details.get('chassis',{});port=details.get('port',{})
            if not isinstance(chassis,dict) or not isinstance(port,dict):continue
            for system in chassis.values():
                if not isinstance(system,dict):continue
                identity=system.get('id',{});remote=port.get('id',{})
                if not isinstance(identity,dict) or not isinstance(remote,dict):continue
                # Keep the identifier subtype. Never equate a MAC-style port ID to a port number.
                if identity.get('type')=='mac':output.append({'interface':name,'chassis_mac':identity.get('value',''),'port_id':str(remote.get('value',''))[:100],'port_id_type':str(remote.get('type',''))[:40]})
    return output[:64]


def inventory(root=Path('/sys/class/net')):
    result={'interfaces':[],'neighbors':[],'machine_type':'unknown'}
    try:
        paths=sorted(root.iterdir())[:64]
        for path in paths:
            name=path.name
            if name=='lo' or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,80}',name):continue
            physical=(path/'device').exists()
            kind='physical' if physical else 'bridge' if (path/'bridge').exists() else 'bond' if (path/'bonding').exists() else 'virtual'
            master=(path/'master').resolve().name if (path/'master').exists() else ''
            item={'name':name,'mac':read(path/'address'),'kind':kind,'state':read(path/'operstate'),'carrier':{'1':True,'0':False}.get(read(path/'carrier')),'master':master,'addresses':[],'members':[]}
            members=read(path/'bonding/slaves').split() if kind=='bond' else [p.name for p in (path/'brif').iterdir()] if kind=='bridge' else []
            item['members']=members[:32]
            mode=read(path/'bonding/mode')
            if mode:item['bond_mode']=mode
            active=read(path/'bonding/active_slave')
            if active:item['active_slave']=active
            result['interfaces'].append(item)
    except OSError:pass
    raw=command(['ip','-j','address','show'])
    if raw:
        try:
            addresses=json.loads(raw)
            for interface in result['interfaces']:
                row=next((x for x in addresses if x.get('ifname')==interface['name']),{})
                interface['addresses']=[str(x['local'])[:80] for x in row.get('addr_info',[])[:16] if 'local' in x]
        except (ValueError,TypeError,AttributeError):pass
    raw=command(['lldpcli','-f','json','show','neighbors'])
    if raw:
        try:result['neighbors']=neighbors(json.loads(raw))
        except (ValueError,TypeError,AttributeError):pass
    # systemd-detect-virt exits 1 for bare metal and prints 'none'.
    for flag,kind in (('--container','container'),('--vm','vm')):
        value=command(['systemd-detect-virt',flag])
        if value and value.strip()!='none':result['machine_type']=kind;break
    else:
        # DMI virtualization absence alone is not sufficient to prove physical hardware.
        if read(Path('/sys/class/dmi/id/product_name')):
            try:
                run=subprocess.run(['systemd-detect-virt'],capture_output=True,text=True,timeout=2)
                if run.returncode==1 and run.stdout.strip()=='none':result['machine_type']='physical'
            except (OSError,subprocess.TimeoutExpired):pass
    return result
