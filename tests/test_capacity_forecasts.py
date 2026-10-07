import json
import time
from unittest.mock import Mock,patch
import pytest
from aiticket import capacity_forecasts as capacity,archive_storage,integrations,unifi,log_archive
from test_truenas_workspace import setup,snapshot
from test_log_archive import configure,smb,receive

DAY=capacity.DAY


def history(now,rate=10_000_000,total=1_000_000_000,count=10):
    return [{'at':now-(count-1-i)*DAY,'used':100_000_000+i*rate,'total':total,'headroom':None} for i in range(count)]


def test_linear_growth_rate_and_time_to_limit():
    now=time.time();result=capacity.estimate(history(now),now)
    assert result['state']=='growing' and result['days']==10
    assert result['rate']==10_000_000 and result['eta_days']==81
    assert result['earliest_days']==result['latest_days']==81
    assert result['capacity_at']==now+81*DAY


def test_smb_estimate_uses_account_headroom_not_archive_total():
    now=time.time();rows=history(now,total=10_000_000_000)
    rows[-1]['headroom']=30_000_000
    result=capacity.estimate(rows,now)
    assert result['eta_days']==3 and result['title']=='Capacity approaching'


def test_uncertainty_reflects_variable_observed_growth():
    now=time.time();rows=history(now)
    for i,row in enumerate(rows):row['used']+=i*i*500_000
    result=capacity.estimate(rows,now)
    assert result['state']=='growing'
    assert result['earliest_days']<result['eta_days']<result['latest_days']
    assert 'not a guarantee' in result['reason']


@pytest.mark.parametrize('rate,state',[(0,'stable'),(-5_000_000,'shrinking')])
def test_stable_and_shrinking_have_no_capacity_date(rate,state):
    now=time.time();result=capacity.estimate(history(now,rate),now)
    assert result['state']==state and 'capacity_at' not in result


def test_slow_log_growth_on_large_share_still_has_trend():
    now=time.time();result=capacity.estimate(history(now,rate=5_000_000,total=10**12),now)
    assert result['state']=='growing' and result['rate']==5_000_000
    assert capacity.duration(result['eta_days'])=='over 1 year'


def test_requires_distinct_days_fresh_readings_and_bounded_history():
    now=time.time()
    assert capacity.estimate(history(now,count=6),now)['state']=='insufficient'
    many=[{'at':now-i*60,'used':i,'total':100000} for i in range(100)]
    assert capacity.estimate(many,now)['state']=='insufficient'
    assert capacity.estimate(history(now-1000),now)['state']=='stale'
    assert capacity.estimate(history(now),now,fresh=False)['state']=='stale'
    assert capacity.estimate([{'at':now,'used':float('nan'),'total':100}],now)['state']=='insufficient'
    assert capacity.estimate([{'at':now+DAY,'used':1,'total':100}],now)['state']=='insufficient'
    rows=history(now);rows=rows[:3]+rows[6:]
    assert capacity.estimate(rows,now)['state']=='inconsistent'


def test_cleanup_or_capacity_change_restarts_learning():
    now=time.time();rows=history(now);rows[-1]['total']*=2
    result=capacity.estimate(rows,now)
    assert result['state']=='insufficient' and 'changed' in result['reason']
    rows=history(now);rows[-1]['used']=10_000_000
    assert capacity.estimate(rows,now)['state']=='insufficient'


def test_variable_growth_does_not_claim_reliable_date():
    now=time.time();rows=history(now)
    for i,row in enumerate(rows):row['used']=100_000_000+(40_000_000 if i%2 else 0)+i*1_000_000
    result=capacity.estimate(rows,now)
    assert result['state']=='inconsistent' and 'eta_days' not in result


def test_hourly_newest_sample_identity_and_invalid_values(environment):
    _,store,_=environment;now=time.time()
    with store.connect() as c:
        assert capacity.record(c,'test','m','truenas','Pool',now,1,100)
        assert capacity.record(c,'test','m','truenas','Pool',now-1,0,100)
        for used,total in [(None,100),(float('inf'),100),(True,100),(-1,100),(1,0)]:
            assert not capacity.record(c,'bad','m','truenas','Pool',now,used,total)
        assert not capacity.record(c,'bad','m','truenas','Pool',now-91*DAY,1,100)
    rows=store.rows('SELECT * FROM capacity_samples')
    assert len(rows)==1 and rows[0]['used']==1
    conn={'id':'c','url':'https://one'};pool={'id':1}
    assert capacity.pool_entity('truenas',conn,pool)!=capacity.pool_entity('truenas',{**conn,'url':'https://two'},pool)
    assert capacity.pool_entity('truenas',conn,{}) is None


def test_pool_history_only_uses_actual_capacity_and_backfill_valid_origin(environment):
    _,store,vault=environment;now=time.time();configure(store,vault)
    with patch('time.time',return_value=now-11*DAY):identifier=setup(store,vault)
    # Snapshots before the latest connection save cannot be attributed to its current URL.
    from aiticket.telemetry_archive import record
    for i in range(10):
        snap=snapshot();snap['pools'][0]['used_bytes']=1e12+i*1e10;snap['pools'][0]['available_bytes']=11e12-i*1e10
        record(store,'integration',identifier,'nas',{'readings':json.dumps(snap)},at=now-(9-i)*DAY)
    record(store,'integration',identifier,'nas',{'readings':{'pools':[{'id':1,'used_percent':30}]}},at=now-10*DAY)
    capacity.backfill(store)
    entity=capacity.pool_entity('truenas',integrations.views(store,'nas')[0],{'id':1})
    result=capacity.forecast(store,entity,now=now+1)
    assert result['state']=='growing' and result['days']==11
    assert result['rate_text']=='+10.000 GB/day'
    assert len(store.rows('SELECT * FROM capacity_samples WHERE entity=?',(entity,)))==11
    with store.connect() as c:
        store.audit(c,'integration.saved',identifier)
        c.execute('DELETE FROM capacity_samples')
    store.save('capacity_backfill',0);capacity.backfill(store)
    assert not store.rows('SELECT * FROM capacity_samples')


def test_live_truenas_and_unas_collection_persist_capacity(environment,monkeypatch):
    _,store,vault=environment;identifier=setup(store,vault)
    monkeypatch.setattr('aiticket.truenas.collect',lambda *args:snapshot())
    integrations.refresh(store,vault,store.rows('SELECT * FROM integrations WHERE id=?',(identifier,))[0])
    rows=store.rows('SELECT * FROM capacity_samples')
    assert len(rows)==2 and rows[0]['kind']=='truenas'
    with store.connect() as c:
        unifi.retain(c,{'id':'unas','machine_id':'unas','kind':'drive','url':'https://unas'}, {'sampled_at':time.time(),'readings':{'storage':{'pools':[{'number':1,'usage':20,'capacity':100}]}}})
    assert store.rows("SELECT * FROM capacity_samples WHERE kind='unifi'")[0]['used']==20


def test_local_history_collects_without_smb_or_during_outage(environment,smb):
    _,store,vault=environment
    worker=log_archive.Archiver(store,vault,smb[1]);worker.step()
    assert store.rows("SELECT * FROM capacity_samples WHERE entity='logs:local'")
    configure(store,vault);worker.next_capacity=0;worker.io=Mock(side_effect=OSError('Unavailable'))
    worker.step()
    assert store.rows("SELECT * FROM capacity_samples WHERE entity='logs:local'")
    assert 'error' in store.setting('archive_storage')


def test_forecasts_render_in_pool_and_archive_views(signed_in):
    client,store,vault,_=signed_in;identifier=setup(store,vault);now=time.time()
    store.save('network_log_retention',{'megabytes':1000})
    conn=integrations.views(store,'nas')[0]
    entity=capacity.pool_entity('truenas',conn,{'id':1})
    with store.connect() as c:
        for row in history(now):
            capacity.record(c,entity,'nas','truenas','Archive',row['at'],row['used'],row['total'])
            capacity.record(c,'logs:local',None,'local_logs','Local records',row['at'],row['used'],row['total'])
    host=client.get('/hosts/nas').data
    assert b'Estimated limit in' in host and b'Growth range' in host and b'+10.000 MB/day' in host
    history_page=client.get('/telemetry-history').data
    assert b'Estimated limit in' in history_page and b'configured evidence budget' in history_page
    with store.connect() as c:c.execute('UPDATE capacity_samples SET at=at-2000')
    assert b'Current capacity reading is stale' in client.get('/telemetry-history').data


def test_budget_change_hides_old_forecast_immediately(environment):
    _,store,_=environment;now=time.time()
    with store.connect() as c:
        for row in history(now):capacity.record(c,'logs:local',None,'local_logs','Local',row['at'],row['used'],row['total'])
    store.save('network_log_retention',{'megabytes':1000})
    assert archive_storage.comparison(store,{})['local_storage']['forecast']['state']=='growing'
    store.save('network_log_retention',{'megabytes':2000})
    assert archive_storage.comparison(store,{})['local_storage']['forecast']['state']=='insufficient'


def test_missing_current_pool_capacity_withholds_previous_prediction(environment):
    _,store,vault=environment;identifier=setup(store,vault);now=time.time()
    conn=integrations.views(store,'nas')[0];entity=capacity.pool_entity('truenas',conn,{'id':1})
    with store.connect() as c:
        for row in history(now):capacity.record(c,entity,'nas','truenas','Archive',row['at'],row['used'],row['total'])
    from aiticket.truenas_view import build
    assert build(store,{'id':'nas'},conn)['pools'][0]['forecast']['state']=='growing'
    conn['data']['pools'][0].pop('used_bytes')
    assert build(store,{'id':'nas'},conn)['pools'][0]['forecast']['state']=='stale'


def test_optional_or_malformed_storage_cannot_interrupt_collection(environment):
    _,store,_=environment
    conn={'id':'one','machine_id':None,'url':'https://one'}
    with store.connect() as c:
        for snap in ({'readings':None},{'readings':{'storage':None}},{'readings':{'storage':{'pools':None}}},None):
            capacity.pools(c,'unifi',conn,snap,time.time())
        capacity.pools(c,'unifi',conn,{'readings':{'storage':{'pools':[{'number':1,'usage':200,'capacity':100}]}}},time.time())
    assert not store.rows('SELECT * FROM capacity_samples')
