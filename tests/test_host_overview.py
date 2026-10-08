import json,time
from html.parser import HTMLParser
from aiticket.discovery import validate
from aiticket.metric_history import record,charts
from aiticket.host_overview import prepare


def test_top_processes_missing_cpu_and_check_priority():
    data={'discovery':{'data':{'processes':[{'name':'missing'},{'name':'busy','cpu_percent':200},{'name':'idle','cpu_percent':1},{'name':'second','cpu_percent':40}]}},'checks':[
        {'name':'healthy','enabled':1,'health':'healthy','failures':0},
        {'name':'disabled','enabled':0,'health':'down','failures':1},
        {'name':'failed','enabled':1,'health':'down','failures':1}]}
    prepare(data)
    assert [r['name'] for r in data['top_processes']]==['busy','second','idle']
    assert [r['name'] for r in data['overview_checks']]==['failed','healthy','disabled']


def test_shared_cursor_buckets_preserve_missing_data(environment):
    _,store,_=environment;now=time.time()
    with store.connect() as c:
        record(c,'host','agent',now-50,{'cpu_percent':20})
        record(c,'host','agent',now-250,{'memory_total_bytes':100,'memory_available_bytes':40})
    history=charts(store,{'id':'host','agent':{'id':'a'}},'10m',now)
    cpu,ram=history['charts'][:2]
    assert len(cpu['samples'])==len(ram['samples'])==120
    assert [s['at'] for s in cpu['samples']]==[s['at'] for s in ram['samples']]
    assert sum(s['value'] is not None for s in cpu['samples'])==1
    assert next(s['value'] for s in ram['samples'] if s['value'] is not None)==60


class Lists(HTMLParser):
    def __init__(self):super().__init__();self.in_template=False;self.main_checks=0;self.inventory=0;self.templates=0
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='template':self.in_template=True;self.templates+=1
        if not self.in_template and 'check-item' in attrs.get('class',''):self.main_checks+=1
        if not self.in_template and 'data-host-entry' in attrs:self.inventory+=1
    def handle_endtag(self,tag):
        if tag=='template':self.in_template=False


def test_host_overview_limits_complete_drawers_and_escaped_inventory(signed_in):
    client,store,_,_=signed_in;now=time.time();machine='overview'
    inventory=validate({'processes':[{'name':f'Process {i}','target':f'process{i}','pid':i+1,'cpu_percent':i} for i in range(12)],'containers':[{'name':'<script>bad</script>','target':'docker','state':'running','cpu_percent':4}]})
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Overview test',now))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,telemetry) VALUES(?,?,?,?,?)',('agent',machine,'digest',now,'{}'))
        c.execute('INSERT INTO agent_discovery(machine_id,at,data) VALUES(?,?,?)',(machine,now,json.dumps(inventory)))
        for i in range(10):c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,?,?,60,'medium')",(f'check{i}',machine,f'Check {i}','process','{}'))
    page=client.get('/hosts/'+machine)
    assert page.status_code==200
    parser=Lists();parser.feed(page.text)
    assert parser.main_checks==6 and parser.inventory==4 and parser.templates==3
    assert 'Process 0' in page.text and 'Check 9' in page.text
    assert '<script>bad</script>' not in page.text and '&lt;script&gt;bad&lt;/script&gt;' in page.text
    assert f'action="/hosts/{machine}/container-logs"' in page.text
    assert 'host-inventory-drawer' in page.text and 'data-live-preserve' in page.text


def test_primary_history_is_bounded_and_secondary_metrics_are_retained():
    keys=['cpu_percent','ram_percent','disk_percent','load_1','load_5','load_15','swap_percent','inode_percent','memory_pressure_percent','uptime_hours']
    data={'checks':[],'history':{'charts':[{'key':key} for key in keys]}}
    prepare(data)
    assert [r['key'] for r in data['overview_charts']]==keys[:4]
    assert [r['key'] for r in data['additional_charts']]==keys[4:]
