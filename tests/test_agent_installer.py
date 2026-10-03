import hashlib,subprocess
from pathlib import Path


def test_installer_verifies_complete_bundle_and_rejects_tampering(tmp_path):
    installer=Path('agent/install.sh').resolve()
    names=('agent.py','diagnostics.py','monitoring.py','actions.py','commands.py','aiticket-agent.service')
    (tmp_path/'agent').mkdir()
    sums=[]
    for name in names:
        data=Path('agent',name).read_bytes();(tmp_path/'agent'/name).write_bytes(data)
        sums.append(hashlib.sha256(data).hexdigest()+'  agent/'+name)
    (tmp_path/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
    args=['bash',str(installer),'--source',str(tmp_path),'--verify-only']
    result=subprocess.run(args,capture_output=True,text=True)
    assert result.returncode==0 and 'verified' in result.stdout
    (tmp_path/'agent'/'commands.py').write_text('tampered')
    result=subprocess.run(args,capture_output=True,text=True)
    assert result.returncode!=0 and 'Checksum mismatch: agent/commands.py' in result.stderr
