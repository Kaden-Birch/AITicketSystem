"""Automatic signed compatibility checks, with a simple explicit activation step."""
import time
from .db import uid


def check(store,vault):
    from .ai import bridge_request,BRIDGE_DEFAULTS
    bridge=store.setting('hermes_config',BRIDGE_DEFAULTS);secret=store.setting('hermes_secret')
    if not secret or not bridge.get('url'):raise ValueError('Add the bridge address and connection secret first.')
    try:result=bridge_request(vault,{'id':uid(),'endpoint':bridge['url'],'bridge_secret':secret},'GET','/v1/capabilities',ca=bridge.get('ca'))
    except Exception:
        store.save('hermes_connection',{'state':'Needs attention','at':time.time(),'note':'Cannot connect. Check the address, connection secret and whether the companion service is running.'})
        raise ValueError('Cannot connect to Hermes. Check the address, connection secret and companion service.') from None
    mode=bridge.get('execution_mode','gateway')
    if not isinstance(result,dict) or not isinstance(result.get('workspace_modes',[]),list) or result.get('version')!=1 or result.get('tools')!=(['aiticket_host'] if bridge.get('command_tools') else []) or result.get('model_gateway') is not (mode=='gateway') or result.get('execution_mode','gateway')!=mode or result.get('compatible') is not True:
        store.save('hermes_connection',{'state':'Needs attention','at':time.time(),'note':'Update the companion and match its connection mode and host-tool setting.'})
        raise ValueError('Hermes settings do not match. Update the companion, then match its mode and host-tool setting.')
    # A stale result from an edited connection must never enable admission.
    if store.setting('hermes_config')!=bridge or store.setting('hermes_secret')!=secret:raise ValueError('Connection changed during the check. Save again.')
    store.save_many({'hermes_validation':{'at':time.time(),'url':bridge['url'],'execution_mode':mode,'workspace_modes':[m for m in ('advice','exploration','recovery_proposal') if m in result.get('workspace_modes',[])]},'hermes_connection':{'state':'Connected','at':time.time(),'note':'Connection checked automatically. Use a test investigation to check your model login.'}})
    return result


def refresh(store,vault,now=None):
    """Renew compatibility automatically, off the monitoring thread; failures back off."""
    import json
    now=time.time() if now is None else now
    if not store.setting('hermes_config',{}).get('enabled'):return False
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT value FROM settings WHERE key='hermes_connection'").fetchone()
        connection=json.loads(row[0]) if row else {}
        if connection.get('next_check',0)>now or connection.get('state')=='Connected' and now-connection.get('at',0)<43200:return False
        connection['next_check']=now+300
        c.execute("INSERT INTO settings(key,value) VALUES('hermes_connection',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(connection),))
    try:check(store,vault)
    except ValueError:
        connection=store.setting('hermes_connection',{})
        store.save('hermes_connection',{**connection,'next_check':now+300})
    return True
