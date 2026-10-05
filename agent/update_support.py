"""Updater-only compatibility checks. Never imports or executes agent code."""
import ast
import json
import ssl
import urllib.error
import urllib.request


class CompatibilityError(ValueError):
    pass


def requirements(stage):
    for node in ast.parse((stage/'agent.py').read_text()).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='UPDATE_REQUIREMENTS' for t in node.targets):
            value=ast.literal_eval(node.value)
            if not isinstance(value,dict):raise ValueError('Invalid agent compatibility requirements')
            return value
    return {'protocol':1,'operations':['process_summary','service_status','service_logs']}


def check(identity,version,stage):
    base=identity['server'].rstrip('/')
    if not base.startswith('https://') and not (base.startswith('http://') and identity.get('allow_http') is True):
        raise CompatibilityError('Application address is invalid. Check the saved enrollment address.')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    try:
        opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=identity.get('ca'))))
        payload={'version':version,**requirements(stage)}
        request=urllib.request.Request(base+'/api/agent/update-compatibility',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+identity['credential']})
        with opener.open(request,timeout=10) as reply:
            body=reply.read(8193)
            if len(body)>8192:raise ValueError('Compatibility response too large')
            result=json.loads(body)
        if not isinstance(result,dict):raise ValueError('Invalid compatibility response')
        if result.get('version')!=version or result.get('compatible') is not True:
            raise CompatibilityError('Update the main application first; it does not support this agent release.')
    except urllib.error.HTTPError as error:
        if error.code in (401,403):raise CompatibilityError('Enrollment was rejected. Check that this agent is still linked and authorized.') from None
        if error.code in (404,405,400):raise CompatibilityError('Update the main application first; compatibility could not be confirmed.') from None
        raise CompatibilityError('Application compatibility check failed. Check the application service and try again.') from None
    except CompatibilityError:raise
    except (OSError,ValueError,KeyError,TypeError):
        raise CompatibilityError('Cannot verify application compatibility. Check its address, network and certificate trust, then try again.') from None


def failure_reason(error):
    """Readable release failures without URLs, headers or credentials."""
    if isinstance(error,urllib.error.HTTPError):return 'GitHub release download failed (HTTP '+str(error.code)+'). Check GitHub access and try again.'
    if isinstance(error,ssl.SSLError):return 'Cannot verify the GitHub certificate. Check the host clock and trusted certificates.'
    if isinstance(error,urllib.error.URLError):return 'Cannot reach GitHub to download the release. Check network access and try again.'
    if type(error).__name__=='InvalidSignature':return 'Release signature verification failed. The current agent was kept.'
    if isinstance(error,ValueError):return str(error)[:240] or 'Release validation failed. The current agent was kept.'
    return 'Update files could not be prepared. Check local permissions, free space and the Python runtime.'


def preflight_existing(identity_path,stage):
    """Installer upgrades check compatibility before stopping the existing service."""
    from pathlib import Path
    identity_path=Path(identity_path);stage=Path(stage)
    if not identity_path.exists():return
    try:
        version=next(ast.literal_eval(node.value) for node in ast.parse((stage/'agent.py').read_text()).body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in node.targets))
        check(json.loads(identity_path.read_text()),version,stage)
    except CompatibilityError as error:raise SystemExit(str(error)) from None
    print('Application compatibility confirmed; existing enrollment preserved.')
