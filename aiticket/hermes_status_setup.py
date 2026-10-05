"""Install one read-only status MCP entry into an existing normal Hermes profile."""
import argparse,json,os,sys,time
from pathlib import Path
from .security import validate_url


def install(config,server,secret_file,python,source,ca=None,allow_http=False):
    if allow_http:os.environ['AITICKET_ALLOW_INSECURE_HTTP']='1'
    server=validate_url(server,('https',)).rstrip('/')
    config=Path(config).expanduser();secret_file=Path(secret_file).expanduser().resolve()
    if not secret_file.is_file() or not os.access(secret_file,os.R_OK) or secret_file.stat().st_mode & 0o077:raise ValueError('Use a readable private connection-secret file (mode 0600).')
    if not 16<=len(secret_file.read_text().strip())<=2048:raise ValueError('The connection secret is incomplete.')
    if not Path(python).is_file() or not Path(source,'aiticket','command_tools.py').is_file():raise ValueError('Choose the installed bridge interpreter and repository paths.')
    raw=config.read_text() if config.exists() else ''
    try:
        import yaml
        cfg=yaml.safe_load(raw) or {}
        encode=lambda value:yaml.safe_dump(value,sort_keys=False)
    except ImportError:
        try:cfg=json.loads(raw) if raw.strip() else {}
        except ValueError:raise ValueError('Run this setup with your Hermes Python interpreter, which includes its YAML reader.') from None
        encode=lambda value:json.dumps(value,indent=2)+'\n' # JSON is also valid YAML.
    if not isinstance(cfg,dict) or not isinstance(cfg.get('mcp_servers',{}),dict):raise ValueError('The existing Hermes configuration needs review before adding this connection.')
    args=['-m','aiticket.command_tools','--status-only','--server',server,'--secret-file',str(secret_file)]
    if ca:args.extend(['--ca',str(Path(ca).expanduser().resolve())])
    if allow_http:args.append('--allow-http')
    entry={'command':str(Path(python).resolve()),'args':args,'env':{'PYTHONPATH':str(Path(source).resolve())}}
    if cfg.get('mcp_servers',{}).get('aiticketsystem')==entry:return False
    if 'aiticketsystem' in cfg.get('mcp_servers',{}):raise ValueError('An AITicketSystem entry already exists. Review it before replacing it.')
    if raw:
        backup=config.with_name(config.name+'.before-aiticket-'+str(time.time_ns()))
        descriptor=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'w') as f:f.write(raw)
    cfg.setdefault('mcp_servers',{})['aiticketsystem']=entry
    config.parent.mkdir(parents=True,exist_ok=True)
    temporary=config.with_name(config.name+'.aiticket-'+str(time.time_ns()))
    descriptor=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(descriptor,'w') as f:f.write(encode(cfg))
        os.replace(temporary,config)
    finally:temporary.unlink(missing_ok=True)
    return True


def main():
    parser=argparse.ArgumentParser(description='Connect a normal Hermes profile to read-only AITicketSystem status.')
    parser.add_argument('--server',required=True);parser.add_argument('--secret-file',required=True);parser.add_argument('--python',required=True);parser.add_argument('--source',default=str(Path(__file__).resolve().parents[1]));parser.add_argument('--config',default=str(Path(os.environ.get('HERMES_HOME',Path.home()/'.hermes'))/'config.yaml'));parser.add_argument('--ca');parser.add_argument('--allow-http',action='store_true')
    args=parser.parse_args()
    try:changed=install(args.config,args.server,args.secret_file,args.python,args.source,args.ca,args.allow_http)
    except (ValueError,OSError) as e:raise SystemExit(str(e)) from None
    print('Hermes status connection '+('added; existing settings backed up.' if changed else 'is already configured.'))
    print('Start a new Hermes session, or use /reload-mcp, then ask for a host status report.')


if __name__=='__main__':main()
