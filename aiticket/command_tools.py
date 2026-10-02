"""One compact remote-host tool for isolated Hermes and independent MCP clients."""
import argparse,json,os,sys,uuid,time
from pathlib import Path
import requests
from .security import hermes_headers,validate_url

NAME='aiticket_host'
SCHEMA={'name':NAME,'description':'Remote shell on authorized hosts. targets lists machine IDs, observed agent connection addresses, freshness and shell availability. run queues one arbitrary command; status returns exit/stdout/stderr; cancel stops local work. Approval policy and OS privileges apply. proxmox requests any token-permitted API endpoint on a linked connection; proxmox_status inspects the durable request. block records a need for human clarification/permission and notifies the administrator. resolve requests verified incident closure and recovery notification. Unknown outcomes must never be replayed.','parameters':{'type':'object','properties':{'action':{'type':'string','enum':['targets','run','status','cancel','proxmox','proxmox_status','resolve','block']},'summary':{'type':'string','description':'Brief repair explanation for resolve. Closure waits for fresh healthy monitoring after this run; AI text alone never proves recovery.'},'connection_id':{'type':'string'},'method':{'type':'string','enum':['GET','POST','PUT','DELETE']},'path':{'type':'string','description':'Relative Proxmox API path, e.g. /nodes/node/qemu/100/status/start. Token controls all API permissions.'},'params':{'type':'object','additionalProperties':True},'machine_id':{'type':'string'},'command':{'type':'string'},'id':{'type':'string','description':'Stable command UUID; reuse only for the exact same run. Required for status/cancel.'},'offset':{'type':'integer','minimum':0,'maximum':65536}},'required':['action'],'additionalProperties':False}}


def invoke(server,args,credential=None,job=None,secret=None,ca=None):
    args=dict(args);offset=args.pop('offset',0)
    if type(offset) is not int or not 0<=offset<=65536: raise ValueError('Invalid output offset.')
    if args.get('action') in ('run','proxmox'): args.setdefault('id',str(uuid.uuid4()))
    body=json.dumps(args,separators=(',',':'),sort_keys=True).encode()
    path='/api/hermes/'+job+'/command' if job else '/api/operations/command'
    headers={'Authorization':'Bearer '+credential,'Content-Type':'application/json'} if job else hermes_headers(secret,body,args.get('id',str(uuid.uuid4())))
    deadline=time.monotonic()+20 if args.get('action')=='status' else time.monotonic()
    try:
      while True:
        if not job: headers=hermes_headers(secret,body,args.get('id',str(uuid.uuid4())))
        with requests.post(server.rstrip('/')+path,data=body,headers=headers,timeout=(3,10),verify=ca or True,allow_redirects=False,stream=True) as response:
            raw=response.raw.read(512001)
            if len(raw)>512000: raise ValueError('Command API returned an oversized response.')
            if response.status_code!=200:
                from .diagnostics import redact
                try: detail=json.loads(raw).get('error','Command API rejected the request.')
                except (ValueError,AttributeError): detail='Command API rejected the request.'
                return json.dumps({'state':'rejected' if 400<=response.status_code<500 else 'unknown','http_status':response.status_code,'error':redact(str(detail))[:500],'id':args.get('id'),'note':'Inspect this UUID before submitting another operation; do not replay unknown outcomes.'})
            result=json.loads(raw)
        if result.get('state') not in ('pending','dispatched','running') or time.monotonic()>=deadline: break
        time.sleep(1)
    except Exception as exc:
        lookup=args.get('action') in ('status','proxmox_status','targets')
        return json.dumps({'state':'lookup_failed' if lookup else 'unknown','error_type':type(exc).__name__,'error':'Status/target lookup failed; this does not establish whether an operation was dispatched.' if lookup else 'Request failed or delivery is ambiguous. Do not replay the command. Check its UUID/status in the host workspace.','id':args.get('id')})
    if result.get('result') and 'stdout' in result['result']:
        full=result['result'];result['result']={**full,**{k:full[k][offset:offset+2048] for k in ('stdout','stderr')}}
        result['more_output']=any(len(full[k])>offset+2048 for k in ('stdout','stderr'))
    if result.get('result') and 'body' in result['result']:
        text=json.dumps(result['result']['body']);result['result']['body']=text[offset:offset+2048];result['more_output']=len(text)>offset+2048
    result.pop('command',None)
    return json.dumps(result)


def register(job,gateway,ca=None):
    from tools.registry import registry
    registry.register(name=NAME,toolset='aiticket',schema=SCHEMA,handler=lambda args,**kwargs:invoke(gateway,args,credential=job['credential'],job=job['execution_id'],ca=ca),check_fn=lambda:True)


def main():
    parser=argparse.ArgumentParser(description='AITicket remote command MCP server (stdio)')
    parser.add_argument('--server',required=True);parser.add_argument('--secret-file',required=True);parser.add_argument('--ca');parser.add_argument('--allow-http',action='store_true')
    args=parser.parse_args()
    if args.allow_http: os.environ['AITICKET_ALLOW_INSECURE_HTTP']='1'
    server=validate_url(args.server,('https',));secret=Path(args.secret_file).read_text().strip()
    if len(secret)<16: raise SystemExit('Invalid operations shared secret.')
    for line in sys.stdin:
        try:
            if len(line)>65536: raise ValueError('Request too large.')
            request=json.loads(line)
            if 'id' not in request: continue
            method=request.get('method');params=request.get('params',{})
            if method=='initialize': result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'aiticket-commands','version':'1.0'}}
            elif method=='ping': result={}
            elif method=='tools/list': result={'tools':[{'name':NAME,'description':SCHEMA['description'],'inputSchema':SCHEMA['parameters']}]}
            elif method=='tools/call' and params.get('name')==NAME: result={'content':[{'type':'text','text':invoke(server,params.get('arguments',{}),secret=secret,ca=args.ca)}]}
            else: raise ValueError('Unsupported method/tool.')
            response={'jsonrpc':'2.0','id':request['id'],'result':result}
        except Exception: response={'jsonrpc':'2.0','id':request.get('id') if isinstance(locals().get('request'),dict) else None,'error':{'code':-32602,'message':'Invalid command tool request'}}
        print(json.dumps(response),flush=True)


if __name__=='__main__': main()
