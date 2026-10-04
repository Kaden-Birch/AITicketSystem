"""Adapt the shared durable agent protocol to Windows; run only through launcher."""
import importlib.util,os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from platform_support import locks


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module


def prepare(bundle,root):
    bundle=Path(bundle);sys.path.insert(0,str(bundle));sys.modules['fcntl']=locks
    import backend
    diagnostics=load('diagnostics',bundle/'diagnostics.py');diagnostics.load_policy=backend.load_policy;diagnostics.capabilities=backend.capabilities;diagnostics.execute=backend.diagnostic
    commands=load('commands',bundle/'commands.py');commands.execute=backend.execute_command;commands.policy_config=backend.policy_config
    actions=load('actions',bundle/'actions.py');actions.execute=backend.action
    monitoring=load('monitoring',bundle/'monitoring.py');monitoring.evaluate=backend.evaluate
    # Docker's API is shared; preserve Windows PATH for its CLI.
    run=monitoring.subprocess.run
    def windows_run(argv,**kwargs):
        kwargs.pop('env',None);return run(argv,**kwargs)
    # Avoid replacing the shared subprocess module; inject a per-module proxy.
    monitoring.subprocess=types.SimpleNamespace(run=windows_run,DEVNULL=__import__('subprocess').DEVNULL,PIPE=__import__('subprocess').PIPE,SubprocessError=__import__('subprocess').SubprocessError)
    agent=load('agent',bundle/'agent.py');agent.host_info=backend.host_info;agent.telemetry=backend.telemetry;agent.network_info=lambda:backend.inventory()
    return agent


def main():
    root=Path(__file__).resolve().parent.parent.parent.parent
    agent=prepare(Path(__file__).resolve().parent.parent,root)
    command=sys.argv[1] if len(sys.argv)>1 else 'run'
    sys.argv=[sys.argv[0],command,'--state',str(root/'state'/'identity.json'),'--policy',str(root/'config'/'policy.json'),*sys.argv[2:]]
    agent.main()

if __name__=='__main__':main()
