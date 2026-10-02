import uuid,time,json
from unittest.mock import patch
import pytest
from aiticket import commands,proxmox_operations as ops
from aiticket.host_access import read_only
from test_commands import setup,dispatch
from test_proxmox_operations import host,payload,response


@pytest.mark.parametrize('command',['hostname; ip -brief address; ip route','id; uptime; df -h; free -h','systemctl --failed --no-pager','systemctl status planner.service --no-pager','journalctl -p err --since "2 hours ago" --no-pager -n 200','cat /proc/pressure/memory','sudo -n /usr/bin/df -h','ip -j address show'])
def test_recognized_read_commands(command):assert read_only(command)


@pytest.mark.parametrize('command',['reboot','shutdown now','systemctl restart planner.service','hostname new-name','ip route add default via 10.0.0.1','ss -K','journalctl --vacuum-time=1s','date --set=now','date 01011200','python3 -c "print(1)"','cat /proc/uptime > /etc/test','uptime; rm -rf /tmp/test','echo $(reboot)','/tmp/uptime','uptime &','sudo -u root reboot'])
def test_unknown_or_mutating_commands_are_not_readonly(command):assert not read_only(command)


@pytest.mark.parametrize('mode,command,state',[('readonly','ip -brief address','pending'),('guarded','hostname; uptime','pending'),('guarded','systemctl restart planner.service','awaiting'),('immediate','systemctl restart planner.service','pending')])
def test_mode_changes_actual_shell_dispatch(environment,mode,command,state):
    _,store,vault=environment;machine=setup(store)
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','approval':mode})
    identifier=str(uuid.uuid4());commands.queue(store,vault,machine,command,identifier)
    assert commands.view(store,vault,identifier)['state']==state
    with store.connect() as c: jobs=commands.poll(c,store,vault,'shell-agent',time.time())
    assert bool(jobs)==(state=='pending')


def test_readonly_rejects_mutation_and_mode_change_does_not_preapprove_old_request(environment):
    _,store,vault=environment;machine=setup(store)
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','approval':'readonly'})
    with pytest.raises(ValueError,match='read-only'):commands.queue(store,vault,machine,'reboot',str(uuid.uuid4()))
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','approval':'guarded'})
    old=str(uuid.uuid4());commands.queue(store,vault,machine,'reboot',old)
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','approval':'immediate'})
    assert commands.view(store,vault,old)['state']=='cancelled'
    new=str(uuid.uuid4());commands.queue(store,vault,machine,'reboot',new)
    assert commands.view(store,vault,new)['state']=='pending'


@pytest.mark.parametrize('mode,method,state',[('readonly','GET','completed'),('guarded','GET','completed'),('guarded','POST','awaiting'),('immediate','POST','completed')])
def test_modes_apply_to_proxmox_api(environment,mode,method,state):
    _,store,vault=environment;machine,_=host(store,vault)
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','external':'yes','approval':mode})
    with patch('aiticket.proxmox_operations.requests.request',return_value=response()) as request:
        identifier=ops.queue(store,vault,machine,payload(method),external=True)
        assert ops.view(store,vault,identifier)['state']==state
        assert request.called==(state=='completed')
    if mode=='readonly':
        with pytest.raises(ValueError,match='read-only'):ops.queue(store,vault,machine,payload('DELETE'),external=True)


def test_host_settings_one_choice_enables_ai_and_full_dispatch(signed_in):
    client,store,vault,csrf=signed_in;machine=setup(store)
    page=client.get('/hosts/'+machine)
    assert b'Host settings' in page.data and b'Configure remote command access' not in page.data and b'Edit host &amp;' not in page.data
    page=client.get('/hosts/'+machine+'/settings')
    assert page.status_code==200 and b'Full access' in page.data
    result=client.post('/hosts/'+machine+'/settings',data={'csrf':csrf,'access_mode':'immediate','timeout':'120','output_limit':'8192'})
    assert result.status_code==302
    policy=store.rows('SELECT * FROM command_policies WHERE machine_id=?',(machine,))[0]
    assert policy['enabled']==policy['hermes']==policy['external']==1 and policy['approval']=='immediate'
    identifier=str(uuid.uuid4());commands.queue(store,vault,machine,'reboot',identifier)
    assert commands.view(store,vault,identifier)['state']=='pending'
    assert dispatch(store,vault,identifier)['id']==identifier


def test_full_access_preapproved_ai_command_runs_after_completed_session(environment):
    from test_codex_mode import configure
    from aiticket import ai
    from aiticket.handoff import release,pause
    app,store,vault=environment;incident=configure(store,vault,command_tools=True)
    with store.connect() as c:c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES('full-agent','m','fixture',?,'{\"shell_commands\":true}')",(time.time(),))
    commands.configure(store,'m',{'enabled':'yes','hermes':'yes','approval':'immediate'})
    job=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    identifier=str(uuid.uuid4());commands.queue(store,vault,'m','hostname; ip -brief address',identifier,incident,job)
    with store.connect() as c:
        row=c.execute('SELECT * FROM ai_jobs WHERE id=?',(job,)).fetchone()
        c.execute("UPDATE ai_jobs SET state='completed' WHERE id=?",(job,));release(c,row)
        result=commands.poll(c,store,vault,'full-agent',time.time())
    assert result and result[0]['id']==identifier
    current=store.rows('SELECT generation FROM incident_control WHERE incident_id=?',(incident,))[0]['generation']
    pause(store,incident,current)
    assert not commands.permission(store,'full-agent',{'id':identifier,'dispatch_token':result[0]['dispatch_token']})['allowed']
