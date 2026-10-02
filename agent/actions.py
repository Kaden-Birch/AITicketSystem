"""Locally allowlisted actions. No privilege escalation, shell or arbitrary argv."""
import subprocess
import time


def execute(job,policy):
    if job.get('operation') in ('host_restart','host_shutdown'):
        return execute_power(job,policy)
    cfg=policy.get('recovery',{})
    params=job.get('parameters',{})
    if not cfg.get('enabled') or not cfg.get('validated') or job.get('operation')!='service_restart' or job.get('expires',0)<=time.time() or not isinstance(params,dict) or set(params)!={'service_id','unit'}:
        raise ValueError('Local recovery capability is disabled or invalid.')
    unit=policy['services'].get(params['service_id'])
    if params['service_id'] not in cfg.get('services',[]) or unit!=params['unit']:
        raise ValueError('Exact service mapping is not locally allowed.')
    try:
        status=subprocess.run(['/usr/bin/systemctl','show','--no-pager','--property=Id,LoadState,ActiveState','--',unit],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=False,env={'PATH':'/usr/bin:/bin','LANG':'C','SYSTEMD_PAGER':''},timeout=5,check=False)
        if status.returncode or len(status.stdout)>16000:
            return {'status':'failed','output':'Local service precondition could not be verified; no restart attempted.'}
        properties=dict(line.split('=',1) for line in status.stdout.decode(errors='replace').splitlines() if '=' in line)
        if properties.get('Id')!=unit or properties.get('LoadState')!='loaded' or properties.get('ActiveState')!='failed' or job['expires']<=time.time():
            return {'status':'failed','output':'Local exact service is no longer loaded/failed or the delivery expired; no restart attempted.'}
        result=subprocess.run(['/usr/bin/systemctl','restart','--',unit],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,env={'PATH':'/usr/bin:/bin','LANG':'C','SYSTEMD_PAGER':''},timeout=10,check=False)
        return {'status':'completed' if result.returncode==0 else 'failed','output':'Service manager accepted the restart.' if result.returncode==0 else 'Service manager rejected or failed the restart. No automatic retry.'}
    except subprocess.TimeoutExpired:
        return {'status':'unknown','output':'Service manager timed out; outcome must be independently checked. Never replay automatically.'}
    except OSError:
        return {'status':'failed','output':'Service manager could not be started. No automatic retry.'}


def execute_power(job,policy):
    cfg=policy.get('power',{})
    if not cfg.get('enabled') or not cfg.get('validated') or job.get('operation') not in cfg.get('operations',[]) or job.get('parameters')!={} or job.get('expires',0)<=time.time():
        raise ValueError('Local host power permission is disabled, changed or expired.')
    operation={'host_restart':'reboot','host_shutdown':'poweroff'}[job['operation']]
    try:
        result=subprocess.run(['/usr/bin/systemctl','--no-ask-password',operation],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,env={'PATH':'/usr/bin:/bin','LANG':'C'},timeout=10,check=False)
        return {'status':'completed' if result.returncode==0 else 'failed','output':'Power request accepted; state requires independent verification.' if result.returncode==0 else 'Power permission or request rejected; no automatic retry.'}
    except subprocess.TimeoutExpired:
        return {'status':'unknown','output':'Power acceptance unknown; never replay automatically.'}
    except OSError:
        return {'status':'failed','output':'Power command unavailable; no automatic retry.'}
