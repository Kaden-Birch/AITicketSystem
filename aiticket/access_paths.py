"""Bounded, credential-free DNS/TLS/HTTP evidence from the application server."""
import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit
from pathlib import Path
from .security import validate_url


def configuration(values, kind='access_path'):
    url=validate_url(values.get('url','').strip())
    parsed=urlsplit(url)
    if parsed.query:
        raise ValueError('Use a health URL without query parameters or tokens.')
    if kind=='certificate' and parsed.scheme!='https':
        raise ValueError('Certificate checks require HTTPS.')
    result={'url':url,'status':int(values.get('expected_status',values.get('status',200))),
            'expiry_days':int(values.get('expiry_days',30))}
    if not 100<=result['status']<=599 or not 1<=result['expiry_days']<=365:
        raise ValueError('Choose a valid HTTP status and certificate warning of 1–365 days.')
    public=values.get('public_url','').strip()
    if public:
        validate_url(public)
        if urlsplit(public).query or public==url:
            raise ValueError('Use a distinct public URL without query parameters or tokens.')
        result['public_url']=public
        result['public_status']=int(values.get('public_status',result['status']))
        if not 100<=result['public_status']<=599:raise ValueError('Choose a valid public HTTP status.')
    ca=values.get('ca','')
    if ca is True:ca=''
    if not isinstance(ca,str) or (ca and not Path(ca).is_file()):raise ValueError('Use the readable CA file path inside the application container.')
    if ca:result['ca']=ca
    expected=values.get('expected_ips','')
    if isinstance(expected,list):
        if any(not isinstance(x,str) for x in expected):raise ValueError('Use valid DNS IP addresses.')
        expected=','.join(expected)
    if not isinstance(expected,str):raise ValueError('Use valid DNS IP addresses.')
    addresses=[str(ipaddress.ip_address(x.strip())) for x in expected.split(',') if x.strip()]
    if len(addresses)>16:raise ValueError('Use at most 16 expected DNS addresses.')
    if addresses:result['expected_ips']=list(dict.fromkeys(addresses))
    return result


def endpoint(url, expected_status=200, expiry_days=30, expected_ips=(), mode='access_path', ca=None):
    """Runs in an expendable subprocess; its parent bounds even stuck DNS calls."""
    validate_url(url)
    parsed=urlsplit(url);host=parsed.hostname;port=parsed.port or (443 if parsed.scheme=='https' else 80)
    result={'host':host,'port':port,'scheme':parsed.scheme,'healthy':False}
    try:
        addresses=list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))[:64]
        if not addresses:raise socket.gaierror()
        literal=False
        try:ipaddress.ip_address(host);literal=True
        except ValueError:pass
        matches=not expected_ips or set(addresses)==set(expected_ips)
        result['dns']={'state':'mismatch' if not matches else 'literal' if literal else 'healthy','addresses':addresses,'expected':list(expected_ips)}
        if mode=='dns':
            result.update(healthy=matches,stage='dns',reason='DNS addresses match.' if matches else 'Resolved addresses differ from the expected set.')
            return result
        context=ssl.create_default_context()
        if ca:context.load_verify_locations(cafile=ca)
        context.set_alpn_protocols(['http/1.1'])
        connection=(http.client.HTTPSConnection(host,port,timeout=3,context=context) if parsed.scheme=='https'
                    else http.client.HTTPConnection(host,port,timeout=3))
        # Pin the HTTP/TLS request to the DNS result, while retaining Host and SNI.
        selected=[None]
        def connect(address, timeout=3, source_address=None):
            deadline=time.monotonic()+4
            for ip in addresses:
                remaining=deadline-time.monotonic()
                if remaining<=0:break
                try:
                    sock=socket.create_connection((ip,port),timeout=min(timeout,remaining),source_address=source_address)
                    sock.settimeout(3);selected[0]=ip
                    result['transport']={'state':'healthy','address':ip}
                    return sock
                except OSError:continue
            raise TimeoutError('No resolved address connected')
        connection._create_connection=connect
        try:
            connection.connect()
            result['transport']={'state':'healthy','address':selected[0]}
            certificate_ok=True
            if parsed.scheme=='https':
                certificate=connection.sock.getpeercert()
                expires=ssl.cert_time_to_seconds(certificate['notAfter'])
                days=(expires-time.time())/86400
                certificate_ok=days>expiry_days
                result['certificate']={'state':'healthy' if certificate_ok else 'expiring','expires_at':expires,'days_remaining':round(days,1),'warning_days':expiry_days,'verified':True}
            else:result['certificate']={'state':'not_applicable'}
            if mode=='certificate':
                result.update(healthy=certificate_ok and matches,stage='certificate',reason='Verified certificate.' if certificate_ok else 'Certificate approaches expiry.')
                return result
            connection.request('GET',(parsed.path or '/')+('?' + parsed.query if parsed.query else ''),headers={'User-Agent':'AITicketSystem-access-monitor','Accept':'*/*'})
            response=connection.getresponse()
            status=response.status
            result['http']={'state':'healthy' if status==expected_status else 'unexpected_status','status_code':status,'expected_status':expected_status}
            result.update(healthy=matches and certificate_ok and status==expected_status,
                          stage='dns' if not matches else 'certificate' if not certificate_ok else 'http',
                          reason='Access path healthy.' if matches and certificate_ok and status==expected_status else 'DNS addresses differ.' if not matches else 'Certificate approaches expiry.' if not certificate_ok else 'Unexpected HTTP response.')
            # No response bodies, redirect destinations or request paths are retained.
        finally:connection.close()
    except socket.gaierror:
        result.update(stage='dns',reason='Name resolution failed.',dns={'state':'failed'})
    except ssl.SSLCertVerificationError as exc:
        result.update(stage='certificate',reason={10:'Certificate expired.',9:'Certificate is not valid yet.',62:'Certificate hostname does not match.'}.get(exc.verify_code,'Certificate validation failed.'),certificate={'state':'invalid','verified':False,'verify_code':exc.verify_code})
    except ssl.SSLError:
        result.update(stage='certificate',reason='TLS handshake failed.',certificate={'state':'handshake_failed','verified':False})
    except (OSError,http.client.HTTPException):
        stage='certificate' if parsed.scheme=='https' and result.get('transport') and not result.get('certificate') else 'http' if result.get('transport') else 'transport'
        result.update(stage=stage,reason={'certificate':'TLS handshake did not complete.','http':'HTTP response failed.','transport':'Connection could not be established.'}[stage])
    return result


def sample(url, status=200, expiry_days=30, expected_ips=(), mode='access_path', ca=None):
    args={'url':url,'expected_status':status,'expiry_days':expiry_days,'expected_ips':expected_ips,'mode':mode,'ca':ca}
    try:
        completed=subprocess.run([sys.executable,'-m','aiticket.access_paths'],input=json.dumps(args),capture_output=True,text=True,timeout=12,check=True)
        result=json.loads(completed.stdout)
        if not isinstance(result,dict):raise ValueError()
        return result
    except subprocess.TimeoutExpired:
        return {'host':urlsplit(url).hostname,'healthy':False,'stage':'timeout','reason':'Access check exceeded its 12-second time limit.'}
    except (subprocess.SubprocessError,ValueError):
        return {'host':urlsplit(url).hostname,'healthy':None,'stage':'collector','reason':'Access evidence could not be collected.'}


def probe(kind,cfg):
    primary=sample(cfg['url'],cfg.get('status',200),cfg.get('expiry_days',30),cfg.get('expected_ips',()),kind,cfg.get('ca'))
    evidence={'vantage':'AITicketSystem server','internal':primary,'reason':primary['reason']}
    if cfg.get('public_url'):
        public=sample(cfg['public_url'],cfg.get('public_status',cfg.get('status',200)),cfg.get('expiry_days',30),ca=cfg.get('ca'))
        evidence['public']=public
        if primary['healthy'] is True and public['healthy'] is False:
            evidence['assessment']='Internal path responds; public '+public.get('stage','access')+' needs attention. Proxy/routing is a lead, not a confirmed cause.'
        elif primary['healthy'] is False and public['healthy'] is True:
            evidence['assessment']='Public path responds; internal access needs attention.'
        elif primary['healthy'] is False and public['healthy'] is False:
            evidence['assessment']='Both paths fail; application or shared infrastructure may be involved.'
        else:evidence['assessment']='Both paths respond.' if primary['healthy'] is True and public['healthy'] is True else 'One or more paths have no reliable result.'
        states=[primary['healthy'],public['healthy']]
        return False if False in states else None if None in states else True,evidence
    return primary['healthy'],evidence


def views(store,machine=None):
    rows=store.rows("SELECT ch.*,m.name AS host,o.at,o.evidence FROM checks ch JOIN machines m ON m.id=ch.machine_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE ch.kind IN ('http','access_path','certificate','dns')"+(' AND ch.machine_id=?' if machine else '')+' ORDER BY m.name,ch.name',(machine,) if machine else ())
    now=time.time()
    for row in rows:
        row['data']=json.loads(row['evidence'] or '{}')
        row['fresh']=bool(row['data'].get('internal') and row['enabled'] and row['at'] is not None and 0<=now-row['at']<=max(180,row['interval']*3))
    return rows


def suggestions(store):
    """Existing URLs are offered, never guessed from IPs or sent with API credentials."""
    result=[];seen={(r['machine_id'],json.loads(r['config']).get('url')) for r in store.rows("SELECT machine_id,config FROM checks WHERE kind IN ('http','access_path','certificate','dns')")}
    rows=store.rows('SELECT machine_id,name,config FROM integrations')
    for row in rows:
        cfg=json.loads(row['config']);url=cfg.get('url')
        if not url:continue
        parsed=urlsplit(url)
        if parsed.query or parsed.username or parsed.password:continue
        key=(row['machine_id'],url)
        if key in seen:continue
        seen.add(key);result.append({**row,'url':url,'ca':cfg.get('ca') if isinstance(cfg.get('ca'),str) else ''})
    return result


if __name__=='__main__':
    try:print(json.dumps(endpoint(**json.load(sys.stdin))))
    except Exception:print(json.dumps({'healthy':None,'stage':'collector','reason':'Access evidence could not be collected.'}))
