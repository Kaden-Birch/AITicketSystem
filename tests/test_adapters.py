from unittest.mock import MagicMock, patch
import pytest
from aiticket.adapters import probe


def test_http_redirect_not_followed(environment):
    _, _, vault = environment
    with patch('aiticket.access_paths.sample',return_value={'healthy':False,'reason':'Unexpected HTTP response.','http':{'status_code':302,'expected_status':200}}) as sample:
        healthy,evidence=probe('http',{'url':'https://192.0.2.10'},vault)
        assert not healthy and evidence['status_code']==302
        assert evidence['internal']['http']['expected_status']==200
        sample.assert_called_once()



def test_proxmox_expected_stopped_guest(environment):
    _, _, vault = environment
    with patch('aiticket.adapters.requests.get') as get:
        get.return_value.json.return_value = {'data':[{'id':'qemu/209','status':'stopped','node':'pve2'}]}
        config = {'url':'https://192.0.2.20:8006','token_id':'monitor@pve!readonly','token_secret':vault.encrypt('test-only-token'),'resource':'qemu/209','expected':'stopped'}
        healthy, evidence = probe('proxmox', config, vault)
        assert healthy and evidence['node'] == 'pve2'
        assert get.call_args.kwargs['verify'] is True
        assert get.call_args.kwargs['headers']['Authorization'] == 'PVEAPIToken=monitor@pve!readonly=test-only-token'
        config['resource'] = 'qemu/999'
        healthy, evidence = probe('proxmox', config, vault)
        assert not healthy and evidence['reason'] == 'Selected resource not present'


def test_tcp_timeout_and_no_commands(environment):
    _, _, vault = environment
    with patch('aiticket.adapters.socket.create_connection') as connect:
        healthy, _ = probe('tcp', {'host':'192.0.2.10','port':443}, vault)
        assert healthy
        connect.assert_called_once_with(('192.0.2.10',443),timeout=5)


def test_no_unverified_or_credential_urls(environment):
    _, _, vault = environment
    with pytest.raises(ValueError):
        probe('http', {'url':'https://user:password@192.0.2.10'}, vault)
    with pytest.raises(ValueError):
        probe('proxmox', {'url':'http://192.0.2.10'}, vault)
