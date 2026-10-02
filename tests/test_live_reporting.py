import json,time,uuid
from aiticket.security import digest


def test_reporting_interval_validation_and_agent_check_cadence(signed_in):
    client,store,_,csrf=signed_in
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('live-host','Live host',?)",(time.time(),))
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('live-check','live-host','Heartbeat','agent','{}',60)")
    assert b'Agent reporting interval' in client.get('/settings').data
    for value in ('19','301'):
        assert client.post('/settings',data={'csrf':csrf,'section':'monitoring','agent_interval':value}).status_code==400
    assert client.post('/settings',data={'csrf':csrf,'section':'monitoring','agent_interval':'20'}).status_code==302
    assert store.setting('agent_interval')==20
    assert store.rows("SELECT interval,next_run FROM checks WHERE id='live-check'")==[{'interval':20,'next_run':0.0}]


def test_live_script_is_authenticated_page_only(signed_in,environment):
    client,_,_,_=signed_in
    assert b'/static/live.js' in client.get('/').data
    app,_,_=environment
    assert b'/static/live.js' not in app.test_client().get('/login').data


def test_heartbeat_returns_interval_on_accept_and_duplicate(environment):
    app,store,_=environment
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('report-host','Report host',?)",(time.time(),))
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('report-agent','report-host',?)",(digest('report-fixture'),))
    store.save('agent_interval',20)
    client=app.test_client();body={'event_id':str(uuid.uuid4()),'telemetry':{},'capabilities':{}}
    for state in ('accepted','duplicate'):
        result=client.post('/api/agent/heartbeat',json=body,headers={'Authorization':'Bearer report-fixture'})
        assert result.status_code==200 and result.json['status']==state
        assert result.json['poll_interval_seconds']==20


def test_live_keys_ignore_named_form_id_controls():
    """Exercise the real key function with the browser's named-control behavior."""
    import shutil,subprocess
    from pathlib import Path
    import pytest
    node=shutil.which('node')
    if not node: pytest.skip('Node is required for JavaScript regression checks')
    source=Path('aiticket/static/live.js').read_text()
    key=source[source.index('  function key(node) {'):source.index('  function edited(node) {')]
    script="""
const assert = require('node:assert/strict');
const Node = {ELEMENT_NODE:1};
"""+key+"""
function form(value, attributeId=null) {
  return {
    nodeType:1, dataset:{},
    // Each parsed form has a distinct input object masquerading as .id.
    id:{value},
    getAttribute(name) {return name==='id'?attributeId:name==='action'?'/unifi':null;},
    matches(selector) {return selector==='form';},
    querySelector(selector) {return selector==='[name="id"]'?{value}:null;}
  };
}
const before=form('nas-connection');
for (let poll=0;poll<100;poll++) assert.equal(key(before),key(form('nas-connection')));
assert.equal(typeof key(before),'string');
assert.notEqual(key(before),key(form('network-connection')));
assert.equal(key(form('nas-connection','settings-form')),'settings-form');
assert.equal(key(form('')),key(form('')));
"""
    subprocess.run([node,'-e',script],check=True,capture_output=True,text=True)
