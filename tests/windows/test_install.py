"""Real SYSTEM task, authenticated heartbeat, command result and reinstall checks."""
import json,os,subprocess,sys,threading,time,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
pytestmark=pytest.mark.skipif(os.name!='nt',reason='Windows scheduled tasks required')


def test_install_and_reinstall_as_system(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'agent'/'windows'))
    from platform_support import ps,powershell,ps_argv
    install_root=tmp_path/'Agent with spaces';(install_root/'state').mkdir(parents=True)
    heartbeats=[];results=[];request_id=str(uuid.uuid4())
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert self.headers['Authorization']=='Bearer fixture-credential'
            reply={}
            if self.path=='/api/agent/heartbeat':
                if not heartbeats:reply['commands']=[{'id':request_id,'dispatch_token':'fixture-token','command':'[Security.Principal.WindowsIdentity]::GetCurrent().User.Value','timeout':15,'output_limit':1024}]
                heartbeats.append(data);reply.update(status='accepted',poll_interval_seconds=20,jobs=[],actions=[])
            elif self.path=='/api/agent/command-permission':reply={'allowed':True}
            elif self.path=='/api/agent/command-result':results.append(data)
            elif self.path=='/api/agent/checks':reply={'checks':[]}
            elif self.path=='/api/agent/updater':reply={'request':None}
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(reply).encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    identity={'server':'http://127.0.0.1:'+str(server.server_port),'allow_http':True,'agent_id':'fixture-agent','credential':'fixture-credential'}
    (install_root/'state'/'identity.json').write_text(json.dumps(identity))
    argv=[powershell(),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(ROOT/'agent'/'windows'/'install.ps1'),'-Root',str(install_root),'-Source',str(ROOT),'-PythonExe',sys.executable]
    try:
        for iteration in range(2):
            run=subprocess.run(argv,capture_output=True,text=True,timeout=180)
            assert run.returncode==0,run.stdout+'\n'+run.stderr
            deadline=time.monotonic()+90
            while time.monotonic()<deadline and (not heartbeats or not results):time.sleep(1)
            log=(install_root/'state'/'agent.log').read_text(errors='replace')
            assert heartbeats,log
            assert heartbeats[-1]['host_info']['os'].startswith('Windows'),heartbeats[-1]
            assert heartbeats[-1]['capabilities']['shell_commands'] is True
            assert results,log
            assert results[0]['result']['state']=='completed',results
            assert results[0]['result']['stdout'].strip()=='S-1-5-18'
            assert json.loads((install_root/'state'/'identity.json').read_text())['credential']==identity['credential']
            assert ps("(Get-ScheduledTask -TaskName 'AITicketAgentUpdater').Principal.UserId") in ('SYSTEM','S-1-5-18')
            allowed=ps("(Get-Acl -LiteralPath '"+str(install_root)+"').Access | ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}").splitlines()
            assert set(allowed)=={'S-1-5-18','S-1-5-32-544'}
        count=len(results);time.sleep(2);assert len(results)==count
    finally:
        for task in ('AITicketAgentUpdater','AITicketAgent'):
            subprocess.run(ps_argv("Get-ScheduledTask -TaskName '"+task+"' -ErrorAction SilentlyContinue | Stop-ScheduledTask;Unregister-ScheduledTask -TaskName '"+task+"' -Confirm:$false -ErrorAction SilentlyContinue"),capture_output=True,timeout=30)
        server.shutdown()
