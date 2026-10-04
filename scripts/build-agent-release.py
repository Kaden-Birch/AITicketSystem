#!/usr/bin/env python3
"""Build signed immutable Linux and Windows bundles with separate stable feeds."""
import argparse,base64,gzip,hashlib,io,json,re,subprocess,tarfile,time
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--key',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()[:12]
source=(root/'agent/agent.py').read_text();base=re.search(r"VERSION = '([^']+)'",source).group(1);version=base+'+'+sha
shared=('agent.py','diagnostics.py','monitoring.py','network.py','actions.py','commands.py','install_verify.py')
published=int(time.time())
for platform,files in (('agent',shared),('windows-agent',shared+('windows/runner.py','windows/backend.py','windows/platform_support.py'))):
 archive_path=out/(platform+'.tar.gz')
 with archive_path.open('wb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w') as archive:
  for name in files:
   data=(root/'agent'/name).read_bytes()
   if name=='agent.py':data=data.replace(("VERSION = '"+base+"'").encode(),("VERSION = '"+version+"'").encode())
   info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;archive.addfile(info,io.BytesIO(data))
 manifest={'version':version,'url':'https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-'+version+'/'+archive_path.name,'sha256':hashlib.sha256(archive_path.read_bytes()).hexdigest(),'published':published,'rollout_minutes':30}
 payload=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();(out/'payload.json').write_bytes(payload)
 subprocess.run(['openssl','pkeyutl','-sign','-inkey',args.key,'-rawin','-in',str(out/'payload.json'),'-out',str(out/'signature')],check=True)
 subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(root/'agent/release-public.pem'),'-rawin','-in',str(out/'payload.json'),'-sigfile',str(out/'signature')],check=True,stdout=subprocess.DEVNULL)
 (out/(platform+'-manifest.json')).write_text(json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode((out/'signature').read_bytes()).decode()}))
(out/'version').write_text(version)
