"""Bounded, optional read-only interface inventory; failures never stop heartbeats."""
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

_PERFORMANCE_SESSION=uuid.uuid4().hex
COUNTERS=('rx_bytes','tx_bytes','rx_errors','tx_errors','rx_dropped','tx_dropped')


def performance_rates(state,network,disks,now=None):
    """Rates from matching device counters only; restarts/resets leave a gap."""
    now=time.monotonic() if now is None else now
    previous=state.get('io_counters',{})
    state['io_counters']={'session':_PERFORMANCE_SESSION,'at':now,'network':network,'disks':disks}
    elapsed=now-previous.get('at',now)
    result={}
    if network:
        for key in COUNTERS[2:]:
            if all(key in row for row in network.values()):result['network_'+key]=sum(row[key] for row in network.values())
    if previous.get('session')!=_PERFORMANCE_SESSION or not 0<elapsed<=900:return result
    for kind,current in [('network',network),('disks',disks)]:
        old=previous.get(kind,{})
        if not current or current.keys()!=old.keys():continue
        deltas=[]
        for name,row in current.items():
            if row.keys()!=old[name].keys():break
            delta={key:value-old[name][key] for key,value in row.items()}
            if any(value<0 for value in delta.values()):break
            deltas.append(delta)
        else:
            if kind=='network':
                for key in COUNTERS:
                    if all(key in row for row in deltas):result['network_'+key+'_per_second']=sum(row[key] for row in deltas)/elapsed
                result['network_interfaces_sampled']=len(deltas)
            else:
                for key in ('read_bytes','write_bytes'):result['disk_'+key+'_per_second']=sum(row[key] for row in deltas)/elapsed
                busy=[row['busy_ms']/elapsed/10 for row in deltas if 'busy_ms' in row]
                if busy:result['disk_busy_percent']=min(100,max(busy))
                timed=[row for row in deltas if all(key in row for key in ('io_ms','io_ops'))]
                count=sum(row['io_ops'] for row in timed)
                if count:result['disk_latency_ms']=sum(row['io_ms'] for row in timed)/count
                result['disk_devices_sampled']=len(deltas)
    return result


def performance(state,net_root=Path('/sys/class/net'),disk_root=Path('/sys/block'),now=None):
    """Linux kernel counters, without probing mounted files or issuing disk I/O."""
    network={};disks={}
    try:
        for path in sorted(net_root.iterdir())[:4096]:
            if len(network)>=64:break
            if path.name=='lo' or path.name.startswith(('veth','docker','br-','virbr','cni','flannel','tun','tap')) or (path/'master').exists():continue
            row={}
            for key in COUNTERS:
                try:
                    value=int(read(path/'statistics'/key))
                    if value>=0:row[key]=value
                except ValueError:pass
            if 'rx_bytes' in row and 'tx_bytes' in row:network[path.name]=row
    except OSError:pass
    try:
        for path in sorted(disk_root.iterdir())[:4096]:
            if len(disks)>=64:break
            try:
                if path.name.startswith(('loop','ram','zram')) or any((path/'slaves').iterdir()):continue
                with (path/'stat').open() as stream:values=[int(v) for v in stream.read(4096).split()]
                if len(values)<11 or any(v<0 for v in values):continue
                disks[path.name]={'read_bytes':values[2]*512,'write_bytes':values[6]*512,'io_ops':values[0]+values[4],'io_ms':values[3]+values[7],'busy_ms':values[9]}
            except (ValueError,OSError):continue
    except OSError:pass
    return performance_rates(state,network,disks,now)


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
            try:
                speed=int(read(path/'speed'))
                if speed>0:item['speed_mbps']=speed
            except ValueError:pass
            for key in COUNTERS:
                try:
                    value=int(read(path/'statistics'/key))
                    if value>=0:item[key]=value
                except ValueError:pass
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
