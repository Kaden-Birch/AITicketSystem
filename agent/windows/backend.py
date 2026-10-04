"""Windows equivalents of monitoring, diagnostics, commands and approved actions."""
import ctypes,json,os,re,shutil,time,platform
from pathlib import Path
from platform_support import literal,ps,ps_argv,query,run,policy as read_policy,system_directory

class MEMORY(ctypes.Structure):
    _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong),*[(name,ctypes.c_ulonglong) for name in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]]


def telemetry(state=None):
    memory=MEMORY();memory.length=ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):raise ctypes.WinError()
    tick=ctypes.windll.kernel32.GetTickCount64;tick.restype=ctypes.c_ulonglong
    disk=shutil.disk_usage(Path(os.environ.get('SystemDrive','C:')+'\\'))
    result={'uptime_seconds':tick()/1000,'cpu_cores':os.cpu_count() or 1,'memory_total_bytes':memory.total,'memory_available_bytes':memory.available,'disk_total_bytes':disk.total,'disk_free_bytes':disk.free}
    idle=ctypes.c_ulonglong();kernel=ctypes.c_ulonglong();user=ctypes.c_ulonglong()
    if state is not None and ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle),ctypes.byref(kernel),ctypes.byref(user)):
        total=kernel.value+user.value;previous=state.get('windows_cpu')
        if previous and total>previous[0]:result['cpu_percent']=max(0,min(100,100*(1-(idle.value-previous[1])/(total-previous[0]))))
        state['windows_cpu']=[total,idle.value]
    # Linux PSI, inodes and load averages have no equivalent. Do not fabricate zeroes.
    return result


def host_info():
    return {'hostname':platform.node()[:200],'os':'Windows '+platform.release(),'kernel':platform.version()[:200],'architecture':platform.machine()[:80]}


def inventory():
    try:rows=query("@(Get-NetAdapter -IncludeHidden | Select-Object -First 64 | ForEach-Object { $a=$_; [pscustomobject]@{name=$a.Name;mac=([string]$a.MacAddress).ToLower().Replace('-',':');kind=$(if($a.HardwareInterface){'physical'}else{'virtual'});state=$(if($a.Status -eq 'Up'){'up'}else{'down'});carrier=($a.Status -eq 'Up');master='';addresses=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 16 -ExpandProperty IPAddress);members=@()} })",limit=60000)
    except Exception:rows=[]
    try:machine=query('Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model') or {}
    except Exception:machine={}
    model=(str(machine.get('Manufacturer',''))+' '+str(machine.get('Model',''))).lower()
    kind='vm' if any(v in model for v in ('virtual machine','vmware','virtualbox','kvm','qemu','xen','hvm domu','parallels','bochs')) else 'physical' if machine.get('Model') else 'unknown'
    return {'interfaces':rows if isinstance(rows,list) else [rows] if rows else [],'neighbors':[],'machine_type':kind}


def load_policy(path):
    p=read_policy(path);services=p.get('services',{})
    if not isinstance(services,dict) or len(services)>20 or any(not re.fullmatch('[A-Za-z0-9_.-]{1,80}',k) or not re.fullmatch('[A-Za-z0-9_.@ -]{1,100}',v) for k,v in services.items()):raise ValueError('Invalid Windows service allowlist')
    recovery=p.get('recovery',{});power=p.get('power',{'enabled':bool(ctypes.windll.shell32.IsUserAnAdmin()),'validated':bool(ctypes.windll.shell32.IsUserAnAdmin()),'operations':['host_restart','host_shutdown']})
    if any(v not in services for v in recovery.get('services',[])) or any(v not in ('host_restart','host_shutdown') for v in power.get('operations',[])):raise ValueError('Invalid recovery policy')
    return {'services':services,'logs':p.get('logs') is True,'recovery':recovery,'power':power}


def capabilities(p):
    result={'operations':['process_summary','service_status']+(['service_logs'] if p['logs'] else []),'services':list(p['services'])}
    recovery=p.get('recovery',{});power=p.get('power',{})
    if recovery.get('enabled') and recovery.get('validated'):result.update(actions=['service_restart'],action_services={s:p['services'][s] for s in recovery.get('services',[])})
    if power.get('enabled') and power.get('validated'):result['power_operations']=power.get('operations',[])
    return result


def policy_config(path):
    p=read_policy(path).get('commands',{})
    if p.get('enabled') is not True:return {'enabled':False}
    timeout=p.get('timeout',3600);limit=p.get('output_limit',65536)
    if type(timeout) is not int or not 5<=timeout<=3600 or type(limit) is not int or not 1024<=limit<=65536:raise ValueError('Invalid command limits')
    return {'enabled':True,'timeout':timeout,'output_limit':limit,'sudo':False}


def execute_command(job,authorize,load_policy):
    cfg=load_policy();command=job.get('command')
    if not cfg.get('enabled') or not isinstance(command,str) or not 1<=len(command)<=16000 or '\0' in command or not authorize():return {'state':'cancelled','exit_code':None,'stdout':'','stderr':'Command permission unavailable.','truncated':False}
    if type(job.get('timeout')) is not int or not 1<=job['timeout']<=3600 or type(job.get('output_limit')) is not int or not 1024<=job['output_limit']<=65536:raise ValueError('Invalid command bounds')
    return run(ps_argv(command),min(job['timeout'],cfg['timeout']),min(job['output_limit'],cfg['output_limit']),lambda:load_policy()==cfg and authorize())


def diagnostic(job,p):
    op=job.get('operation');params=job.get('parameters',{})
    if job.get('expires',0)<=time.time() or op not in capabilities(p)['operations'] or not isinstance(params,dict):raise ValueError('Diagnostic unavailable')
    if op=='process_summary':
        if params:raise ValueError('No process-summary parameters allowed')
        script='Get-Process | Select-Object -First 100 Id,ProcessName'
    else:
        if set(params)!={'service_id'} or params['service_id'] not in p['services']:raise ValueError('Service not locally allowed')
        unit=literal(p['services'][params['service_id']])
        if op=='service_status':script="$s=Get-Service -Name "+unit+"; 'Id='+$s.Name; 'LoadState=loaded'; 'Platform=windows'; 'ActiveState='+$(if($s.Status -eq 'Running'){'active'}elseif($s.Status -eq 'Stopped'){'inactive'}else{'transitioning'}); 'SubState='+$s.Status.ToString()"
        else:script="Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=(Get-Date).AddHours(-24)} -MaxEvents 200 | Where-Object {$_.Properties.Value -contains "+unit+"} | Select-Object -First 50 TimeCreated,Id,LevelDisplayName,Message"
    from diagnostics import redact
    return {'status':'completed','output':redact(ps(script if op=='service_status' else script+' | ConvertTo-Json -Compress -Depth 4',limit=16000))}


def action(job,p):
    op=job.get('operation');params=job.get('parameters',{})
    if job.get('expires',0)<=time.time():raise ValueError('Expired action')
    if op in ('host_restart','host_shutdown'):
        cfg=p.get('power',{})
        if not cfg.get('enabled') or not cfg.get('validated') or op not in cfg.get('operations',[]) or params!={}:raise ValueError('Power action unavailable')
        result=run([str(system_directory()/'shutdown.exe'),'/r' if op=='host_restart' else '/s','/t','15','/d','p:4:1'],10)
    else:
        cfg=p.get('recovery',{})
        if op!='service_restart' or not cfg.get('enabled') or not cfg.get('validated') or set(params)!={'service_id','unit'} or params['service_id'] not in cfg.get('services',[]) or p['services'].get(params['service_id'])!=params['unit']:raise ValueError('Service recovery unavailable')
        unit=literal(params['unit'])
        script="$s=Get-Service -Name "+unit+";if($s.Status -ne 'Stopped'){throw 'Service is no longer stopped'};Start-Service -Name "+unit
        result=run(ps_argv(script),10)
    return {'status':result['state'],'output':'Request accepted; verify the resulting state independently.' if result['state']=='completed' else 'Action failed or delivery uncertain; never replay automatically.'}


def evaluate(check):
    target=check['config']['target'];details={};healthy=None
    try:
        kind=check['kind']
        if kind=='process':
            if target.lower().startswith('service:'):
                status=ps('$s=Get-Service -Name '+literal(target[8:])+" -ErrorAction SilentlyContinue;if($s){$s.Status.ToString()}else{'missing'}");healthy=status=='Running';details={'status':status}
            else:
                names=query('Get-Process | Select-Object -ExpandProperty ProcessName',limit=60000);names=names if isinstance(names,list) else [names]
                healthy=re.sub(r'(?i)\.exe$','',target).casefold() in [str(n).casefold() for n in names]
        elif kind=='smb':
            if not target.startswith('\\\\'):raise ValueError('Use a UNC share path accessible to LocalSystem')
            reply=ps("$p="+literal(target)+";if(!(Test-Path -LiteralPath $p -PathType Container -ErrorAction Stop)){'missing'}else{Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop | Select-Object -First 1 | Out-Null;'accessible'}",timeout=5);healthy=reply=='accessible';details={'status':reply}
        elif kind=='docker':
            from monitoring import docker_probe
            healthy,details=docker_probe(target,check['config'].get('require_health',False))
    except Exception:details={'status':'unknown','reason':'Windows inspection unavailable; check target and LocalSystem permissions'}
    return {'id':check['id'],'config':check['config'],'healthy':healthy,'sampled_at':time.time(),'details':details}


def discovery(state):
    import monitoring
    # Docker discovery is common; Linux /proc collection is replaced below.
    result={'docker_installed':bool(shutil.which('docker')),'containers':[],'processes':[],'warnings':[]}
    if result['docker_installed']:
        try:
            reply=run(['docker','ps','-a','--format','{{json .}}'],timeout=4,limit=60000)
            if reply['state']!='completed':raise ValueError()
            for line in reply['stdout'][:60000].splitlines()[:100]:
                x=json.loads(line);result['containers'].append({'target':x['Names'],'name':x['Names'],'image':x.get('Image',''),'state':x.get('State','unknown'),'status':x.get('Status',''),'ports':x.get('Ports','')})
            reply=run(['docker','stats','--no-stream','--format','{{json .}}'],timeout=4,limit=60000)
            stats={x['Name']:x for x in [json.loads(line) for line in reply['stdout'].splitlines()[:100]]} if reply['state']=='completed' else {}
            for item in result['containers']:
                row=stats.get(item['name'],{})
                for key,out in [('CPUPerc','cpu_percent'),('MemPerc','memory_percent')]:
                    try:item[out]=float(row[key].rstrip('%'))
                    except (KeyError,ValueError):pass
        except Exception:result['warnings'].append('Docker inventory is unavailable. Check the daemon and LocalSystem access.')
    try:
        rows=query("@(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 200 | ForEach-Object { [pscustomobject]@{pid=$_.Id;name=$_.ProcessName;target=$_.ProcessName;memory_bytes=$_.WorkingSet64;cpu_seconds=$_.CPU;started=$(try{$_.StartTime.ToUniversalTime().Ticks}catch{0})} })",limit=60000)
        if isinstance(rows,dict):rows=[rows]
        previous=state.get('discovery_cpu',{});now=time.monotonic();elapsed=now-state.get('discovery_at',now);current={}
        for p in rows:
            identity=str(p['pid'])+':'+str(p.get('started',''));counter=p.get('cpu_seconds')
            if counter is not None:
                current[identity]=counter
                if identity in previous and elapsed>0:p['cpu_percent']=round(max(0,100*(counter-previous[identity])/elapsed),1)
            p.pop('started',None);p.pop('cpu_seconds',None);result['processes'].append(p)
        result['processes_truncated']=len(rows)==200;state['discovery_cpu']=current;state['discovery_at']=now
    except Exception:result['warnings'].append('Process inventory is unavailable.')
    return result
