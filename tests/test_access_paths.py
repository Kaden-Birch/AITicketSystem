import json
import socket
import ssl
import subprocess
import time
from unittest.mock import MagicMock,patch
import pytest
from aiticket import access_paths as ap
from aiticket.adapters import probe
from aiticket.db import uid
from aiticket.engine import observe


def response_connection(status=200,days=60):
    connection=MagicMock()
    connection.sock.getpeercert.return_value={'notAfter':time.strftime('%b %d %H:%M:%S %Y GMT',time.gmtime(time.time()+days*86400))}
    connection.getresponse.return_value.status=status
    return connection


def test_dns_tls_http_same_path_no_redirect_no_body():
    conn=response_connection(302)
    with patch.object(ap.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.4',443))]),patch.object(ap.http.client,'HTTPSConnection',return_value=conn) as https:
        result=ap.endpoint('https://example.test/private?token=hidden')
    assert result['http']['status_code']==302 and not result['healthy']
    assert result['certificate']['verified'] and result['certificate']['days_remaining']>59
    conn.request.assert_called_once()
    assert conn.request.call_args.args[:2]==('GET','/private?token=hidden')
    conn.getresponse.return_value.read.assert_not_called()
    conn.close.assert_called_once()
    assert 'hidden' not in json.dumps(result) and 'private' not in json.dumps(result)
    assert https.call_args.kwargs['context'].verify_mode==ssl.CERT_REQUIRED


def test_expiry_dns_mismatch_and_standalone_dns():
    conn=response_connection(days=5)
    with patch.object(ap.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.4',443))]),patch.object(ap.http.client,'HTTPSConnection',return_value=conn):
        result=ap.endpoint('https://example.test')
        assert not result['healthy'] and result['stage']=='certificate' and result['http']['state']=='healthy'
        result=ap.endpoint('https://example.test',expected_ips=['192.0.2.5'],mode='dns')
        assert not result['healthy'] and result['dns']['state']=='mismatch'
        conn.connect.reset_mock()
        result=ap.endpoint('https://example.test',mode='dns')
        assert result['healthy'];conn.connect.assert_not_called()


def test_dns_tls_transport_failures_are_distinct():
    with patch.object(ap.socket,'getaddrinfo',side_effect=socket.gaierror()):
        assert ap.endpoint('https://example.test')['stage']=='dns'
    conn=response_connection()
    exc=ssl.SSLCertVerificationError();exc.verify_code=10
    with patch.object(ap.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.4',443))]),patch.object(ap.http.client,'HTTPSConnection',return_value=conn):
        conn.connect.side_effect=exc
        result=ap.endpoint('https://example.test')
        assert result['stage']=='certificate' and result['certificate']['verify_code']==10
        conn.connect.side_effect=ConnectionRefusedError()
        assert ap.endpoint('https://example.test')['stage']=='transport'
        conn.connect.side_effect=None;conn.getresponse.side_effect=TimeoutError()
        assert ap.endpoint('https://example.test')['stage']=='http'


def test_bounded_process_unknown_collection_and_public_comparison():
    with patch.object(ap.subprocess,'run',side_effect=subprocess.TimeoutExpired('probe',12)) as run:
        assert ap.sample('https://example.test')['stage']=='timeout'
        assert run.call_args.kwargs['timeout']==12
    with patch.object(ap.subprocess,'run',side_effect=subprocess.CalledProcessError(1,'probe')):
        assert ap.sample('https://example.test')['healthy'] is None
    good={'healthy':True,'reason':'OK','stage':'http'};bad={'healthy':False,'reason':'Failed','stage':'certificate'}
    with patch.object(ap,'sample',side_effect=[good,bad]):
        healthy,data=ap.probe('access_path',{'url':'http://internal.test','public_url':'https://public.test'})
        assert healthy is False and 'certificate needs attention' in data['assessment'] and 'not a confirmed cause' in data['assessment']
    with patch.object(ap,'sample',side_effect=[good,{'healthy':None,'reason':'Missing'}]):
        assert ap.probe('access_path',{'url':'http://internal.test','public_url':'https://public.test'})[0] is None


@pytest.mark.parametrize('values',[{'url':'https://user:secret@example.test'}, {'url':'https://example.test?token=secret'}, {'url':'https://example.test','public_url':'https://example.test'}, {'url':'https://example.test','expiry_days':0}, {'url':'https://example.test','expected_ips':'not-an-IP'}])
def test_validation(values):
    with pytest.raises(ValueError):ap.configuration(values)


def test_create_edit_export_ui_and_maintenance(signed_in):
    client,store,_,csrf=signed_in;machine=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Photos',time.time()))
    values={'csrf':csrf,'machine_id':machine,'kind':'access_path','name':'Photos paths','url':'http://internal.test/health','public_url':'https://photos.example.test/health','expected_status':200,'interval':300,'fail_after':1,'recover_after':1}
    assert client.post('/checks',data=values).status_code==302
    check=store.rows("SELECT * FROM checks WHERE kind='access_path'")[0]
    cfg=json.loads(check['config']);assert cfg['expiry_days']==30 and cfg['public_url'].startswith('https:')
    with patch.object(ap,'sample',side_effect=[{'healthy':True,'reason':'OK','dns':{'state':'healthy','addresses':['192.0.2.4']}},{'healthy':False,'reason':'Expired','stage':'certificate','certificate':{'state':'invalid'}}]):
        healthy,evidence=probe('access_path',cfg,None,store)
    with store.connect() as c:c.execute('UPDATE checks SET maintenance_until=? WHERE id=?',(time.time()+3600,check['id']))
    observe(store,check['id'],healthy,evidence)
    assert not store.rows('SELECT * FROM incidents')
    assert b'public certificate' in client.get('/applications').data
    assert client.get('/hosts/'+machine).status_code==200
    assert client.get('/checks/'+check['id']+'/edit').status_code==200
    from aiticket.inventory import export_inventory,config
    exported=export_inventory(store)['tables']['checks'][0];config(exported['kind'],exported['config'])
    assert exported['config']['public_url']==cfg['public_url']
    values['public_url']='https://new.example.test';assert client.post('/checks/'+check['id']+'/edit',data=values).status_code==302


def test_real_http_subprocess_and_no_follow(tmp_path):
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from threading import Thread
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302);self.send_header('Location','http://example.invalid/never');self.end_headers()
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=ap.sample('http://127.0.0.1:'+str(server.server_port))
        assert result['http']['status_code']==302 and result['certificate']['state']=='not_applicable'
        assert result['dns']['state']=='literal'
    finally:server.shutdown();server.server_close();thread.join()


def test_real_tls_expiry_private_ca_and_http_auto_evidence(tmp_path):
    from datetime import datetime,timedelta,timezone
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from threading import Thread
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=5)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
    certificate=tmp_path/'ca.pem';private=tmp_path/'key.pem'
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM));private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):self.send_response(200);self.end_headers()
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(certificate),str(private));server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        url='https://127.0.0.1:'+str(server.server_port)
        result=ap.sample(url,ca=str(certificate))
        assert result['certificate']['state']=='expiring' and result['http']['status_code']==200
        assert result['transport']['address']=='127.0.0.1'
        healthy,evidence=probe('http',{'url':url,'ca':str(certificate),'expiry_days':1},None)
        assert healthy and evidence['internal']['certificate']['verified']
        invalid=ap.sample(url)
        assert not invalid['healthy'] and invalid['stage']=='certificate' and not invalid['certificate']['verified']
    finally:server.shutdown();server.server_close();thread.join()


def test_try_next_resolved_address():
    conn=response_connection();sock=MagicMock()
    def invoke_connect():conn._create_connection(('example.test',443))
    conn.connect.side_effect=invoke_connect
    with patch.object(ap.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.4',443)),(2,1,6,'',('192.0.2.5',443))]),patch.object(ap.socket,'create_connection',side_effect=[ConnectionRefusedError(),sock]),patch.object(ap.http.client,'HTTPSConnection',return_value=conn):
        result=ap.endpoint('https://example.test')
        assert result['healthy'] and result['transport']['address']=='192.0.2.5'


def test_access_evidence_archived_and_suggestions(signed_in):
    client,store,_,csrf=signed_in;machine=uid();now=time.time()
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Photos',now))
        c.execute('INSERT INTO integrations(id,machine_id,kind,name,config,secret,snapshot) VALUES(?,?,?,?,?,?,?)',(uid(),machine,'plex','Plex',json.dumps({'url':'http://plex.test','interval':60,'ca':True}),'encrypted','{}'))
    assert len(ap.suggestions(store))==1
    assert client.post('/checks',data={'csrf':csrf,'machine_id':machine,'kind':'access_path','name':'Plex access','url':'http://plex.test','interval':300,'fail_after':1,'recover_after':1}).status_code==302
    assert not ap.suggestions(store)
    check=store.rows("SELECT * FROM checks WHERE kind='access_path'")[0]
    evidence={'vantage':'AITicketSystem server','internal':{'healthy':True,'reason':'Access path healthy.','dns':{'state':'healthy','addresses':['192.0.2.5']}}}
    store.save('telemetry_capture_enabled',True)
    observe(store,check['id'],True,evidence)
    archived=store.rows("SELECT payload FROM telemetry_records WHERE kind='check'")
    assert archived and '192.0.2.5' in archived[-1]['payload']
    with store.connect() as c:c.execute('UPDATE observations SET at=? WHERE check_id=?',(now-4000,check['id']))
    assert not ap.views(store)[0]['fresh']
    assert b'Awaiting current result' in client.get('/applications').data
