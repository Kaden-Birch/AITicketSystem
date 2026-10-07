"""Read-only backing-volume capacity, distinct from retention/queue budgets."""
import hashlib
import json
import os
import time
from pathlib import Path
from . import network_logs as logs


def identity(cfg):
    return hashlib.sha256(json.dumps({k:cfg.get(k) for k in ('server','share','folder','namespace','username','domain')},sort_keys=True).encode()).hexdigest()


def meter(total,free,available):
    if any(type(v) is not int for v in (total,free,available)) or total<=0 or not 0<=free<=total or not 0<=available<=total:
        raise ValueError('Storage server did not report valid capacity.')
    used=total-free;percent=used/total*100
    return {'total':total,'used':used,'available':available,'percent':percent,'color':'high' if percent>=90 else 'moderate' if percent>=75 else 'good'}


def human(value):
    if value is None:return 'Unavailable'
    for unit in ('B','KiB','MiB','GiB','TiB','PiB'):
        if value<1024 or unit=='PiB':return f'{value:,.2f} {unit}' if unit!='B' else f'{value:,} B'
        value/=1024


def local(store):
    result=[];by_device={}
    for label,path in [('Application & telemetry',Path(store.path)),('Network logs',logs.database(store))]:
        folder=path.parent
        if not folder.exists():
            result.append({'label':label,'error':'Storage volume is not available.'});continue
        try:
            device=folder.stat().st_dev
            if device not in by_device:
                if hasattr(os,'statvfs'):
                    stat=os.statvfs(folder);unit=stat.f_frsize or stat.f_bsize
                    measured=meter(stat.f_blocks*unit,stat.f_bfree*unit,stat.f_bavail*unit)
                else:
                    import shutil
                    stat=shutil.disk_usage(folder);measured=meter(stat.total,stat.free,stat.free)
                item={'label':label,**measured,'database_bytes':0}
                by_device[device]=item;result.append(item)
            else:item=by_device[device];item['label']+=' + '+label
            for filename in (str(path),str(path)+'-wal',str(path)+'-shm'):
                try:item['database_bytes']+=Path(filename).stat().st_size
                except FileNotFoundError:pass
        except (OSError,ValueError):result.append({'label':label,'error':'Storage volume capacity is unavailable.'})
    return result


def remote(store,cfg):
    data=store.setting('archive_storage',{})
    if data.get('target')!=identity(cfg):return {'configured':bool(cfg.get('server'))}
    return {**data,'configured':bool(cfg.get('server')),'stale':bool(data.get('error') or not data.get('at') or time.time()-data['at']>600)}
