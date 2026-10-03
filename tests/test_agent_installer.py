import hashlib,subprocess
from pathlib import Path


def test_installer_verifies_complete_bundle_and_rejects_tampering(tmp_path):
    installer=Path('agent/install.sh').resolve()
    names=('agent.py','diagnostics.py','monitoring.py','actions.py','commands.py','install_verify.py','aiticket-agent.service')
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


def verified_fixture():
    from agent.install_verify import EXPECTED
    props={**EXPECTED,'ActiveState':'active'}
    status={'Uid':'0 0 0 0','Gid':'0 0 0 0','NoNewPrivs':'0','CapEff':'00000000000000cb'}
    return props,status,['/usr/bin/python3','/opt/aiticket-agent/agent.py','run'],{'enabled':True,'sudo':False}


def test_postflight_accepts_root_and_rejects_actual_unprivileged_process():
    from agent.install_verify import errors
    props,status,args,policy=verified_fixture()
    assert not errors(props,status,args,policy)
    status.update(Uid='1001 1001 1001 1001',Gid='1001 1001 1001 1001',CapEff='0000000000000000')
    failures=errors(props,status,args,policy)
    assert any('root UID/GID' in f for f in failures)
    assert any('capabilities' in f for f in failures)


def test_postflight_rejects_conflicting_dropins_and_invalid_local_policy():
    from agent.install_verify import errors
    props,status,args,policy=verified_fixture()
    props.update(ProtectSystem='strict',ProtectHome='yes',ReadOnlyPaths='/etc',PrivateUsers='yes')
    status['NoNewPrivs']='1';policy['enabled']=False
    failures=errors(props,status,args,policy)
    for expected in ('ProtectSystem','ProtectHome','ReadOnlyPaths','PrivateUsers','NoNewPrivileges','shell execution'):
        assert any(expected in f for f in failures)


def test_postflight_rejects_wrong_service_command_and_missing_process():
    from agent.install_verify import errors
    props,status,args,policy=verified_fixture()
    props['ActiveState']='failed'
    failures=errors(props,{},['/bin/sleep','infinity'],policy)
    assert any('not active' in f for f in failures)
    assert any('installed agent command' in f for f in failures)
