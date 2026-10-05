"""Explicit service relationships reuse the existing check dependency graph."""
import json
from .db import uid


def choices(store):
    from .integrations import views
    apps=[]
    for connection in views(store):
        if connection['kind']!='truenas' or not connection['fresh'] or connection['data'].get('error'):continue
        for app in connection['data'].get('apps',[]):
            apps.append({'value':connection['id']+'|'+app['name'],'name':connection['host']+' · '+app['name']})
    checks=[]
    for row in store.rows("SELECT c.id,c.name,c.config,c.machine_id,m.name host FROM checks c JOIN machines m ON m.id=c.machine_id WHERE c.kind='truenas' AND c.enabled=1 ORDER BY m.name,c.name"):
        if json.loads(row['config']).get('scope')=='pool':checks.append(row)
    return apps,checks


def configure(store,form,cfg):
    application=form.get('nas_application','')
    storage=form.getlist('storage_checks') if hasattr(form,'getlist') else form.get('storage_checks',[])
    apps,checks=choices(store)
    if application and application not in {x['value'] for x in apps}:raise ValueError('Choose a current TrueNAS application, or clear its link.')
    if not isinstance(storage,list) or len(storage)>20 or any(x not in {c['id'] for c in checks} for x in storage):raise ValueError('Choose existing enabled storage checks.')
    cfg['nas_application']=application;cfg['storage_checks']=list(dict.fromkeys(storage))
    return cfg


def sync(c,store,connection,machine,name,cfg):
    group='service:'+connection
    upstream=list(cfg.get('storage_checks',[]))
    linked=cfg.get('nas_application','')
    if linked:
        nas,app=linked.split('|',1)
        row=c.execute("SELECT * FROM integrations WHERE id=? AND kind='truenas'",(nas,)).fetchone()
        if not row:raise ValueError('The linked TrueNAS connection was removed. Review its dependency.')
        config=json.dumps({'connection_id':nas,'scope':'app','target':app})
        check=c.execute("SELECT id FROM checks WHERE kind='truenas' AND config=? AND enabled=1",(config,)).fetchone()
        if check:upstream.append(check['id'])
        else:
            if app not in {x['name'] for x in json.loads(row['snapshot']).get('apps',[])}:raise ValueError('Refresh TrueNAS discovery before adding this application dependency.')
            check=uid();c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,'truenas',?,?,'medium')",(check,row['machine_id'],app+' application',config,json.loads(row['config'])['interval']));upstream.append(check)
    for key in upstream:
        if not c.execute("SELECT 1 FROM checks WHERE id=? AND kind='truenas' AND enabled=1",(key,)).fetchone():raise ValueError('A storage dependency changed. Review the selected checks.')
    c.execute('DELETE FROM application_dependencies WHERE application_id=?',(group,))
    c.execute('DELETE FROM application_checks WHERE application_id=?',(group,))
    if not upstream:
        c.execute('DELETE FROM applications WHERE id=?',(group,));return
    sources=[r['id'] for r in c.execute("SELECT id FROM checks WHERE kind='plex' AND machine_id=? AND enabled=1 AND json_extract(config,'$.connection_id')=?",(machine,connection))]
    if not sources:raise ValueError('Plex monitoring is missing. Restore its checks first.')
    # Prevent cycles involving dependencies that users created in other groups.
    def reaches(node,seen):
        if node in sources:return True
        if node in seen:return False
        return any(reaches(r[0],seen|{node}) for r in c.execute('SELECT upstream_id FROM application_dependencies WHERE check_id=?',(node,)).fetchall())
    if any(reaches(key,set()) for key in upstream):raise ValueError('These dependencies would create a cycle.')
    c.execute('INSERT INTO applications VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name',(group,name+' dependencies'))
    c.executemany('INSERT INTO application_checks VALUES(?,?)',[(group,x) for x in dict.fromkeys([*sources,*upstream])])
    c.executemany('INSERT INTO application_dependencies VALUES(?,?,?)',[(group,source,x) for source in sources for x in dict.fromkeys(upstream)])
