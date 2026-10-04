"""Stable Windows task launcher; outside automatically updated agent code."""
import json,subprocess,sys,time,os
from pathlib import Path
from platform_support import Job,resume
ROOT=Path(__file__).resolve().parent

def main():
    command=sys.argv[1] if len(sys.argv)>1 else 'run'
    while True:
        bundle=Path(json.loads((ROOT/'current.json').read_text())['path']).resolve()
        if bundle.parent!=ROOT/'releases':raise ValueError('Invalid active release')
        args=[sys.executable,str(bundle/'windows'/'runner.py'),command,*sys.argv[2:]]
        if command!='run':return subprocess.call(args)
        logfile=ROOT/'state'/'agent.log'
        if logfile.exists() and logfile.stat().st_size>5_000_000:os.replace(logfile,logfile.with_suffix('.previous.log'))
        with logfile.open('ab',buffering=0) as log:
            process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=0x08000004)
            job=Job(process)
            try:resume(process.pid);process.wait()
            finally:job.close()
        time.sleep(15)

if __name__=='__main__':raise SystemExit(main())
