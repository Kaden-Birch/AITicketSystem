"""Explicit application dependencies; correlation never proves causation or recovery."""
import json
import time
from .db import uid


def save(store,name,check_ids,dependencies=(),identifier=None):
    name=name.strip();check_ids=list(dict.fromkeys(check_ids));dependencies=list(dict.fromkeys(dependencies))
    if not 1<=len(name)<=100 or not 1<=len(check_ids)<=50:raise ValueError('Name the application and select 1–50 checks.')
    if any(x not in check_ids or y not in check_ids or x==y for x,y in dependencies):raise ValueError('Dependencies must connect two selected checks.')
    graph={key:[] for key in check_ids}
    for child,parent in dependencies:graph[child].append(parent)
    def walk(node,path):
        if node in path:raise ValueError('Dependencies cannot form a cycle.')
        for parent in graph[node]:walk(parent,path|{node})
    for node in graph:walk(node,set())
    identifier=identifier or uid()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        for row in c.execute('SELECT check_id,upstream_id FROM application_dependencies WHERE application_id!=?',(identifier,)):
            graph.setdefault(row['check_id'],[]).append(row['upstream_id']);graph.setdefault(row['upstream_id'],[])
        for node in graph:walk(node,set())
        for key in check_ids:
            if not c.execute("SELECT 1 FROM checks WHERE id=? AND kind!='manual'",(key,)).fetchone():raise ValueError('Select existing monitored checks.')
        c.execute('INSERT INTO applications VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name',(identifier,name))
        c.execute('DELETE FROM application_checks WHERE application_id=?',(identifier,))
        c.executemany('INSERT INTO application_checks VALUES(?,?)',[(identifier,x) for x in check_ids])
        c.execute('DELETE FROM application_dependencies WHERE application_id=?',(identifier,))
        c.executemany('INSERT INTO application_dependencies VALUES(?,?,?)',[(identifier,x,y) for x,y in dependencies])
        store.audit(c,'application.saved',identifier,{'checks':len(check_ids),'dependencies':len(dependencies)})
    return identifier


def health(c,identifier,now):
    rows=[dict(r) for r in c.execute('SELECT c.id,c.name,c.kind,c.health,c.enabled,c.interval,m.name AS machine,o.at,o.health AS latest_health FROM application_checks ac JOIN checks c ON c.id=ac.check_id JOIN machines m ON m.id=c.machine_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE ac.application_id=? ORDER BY m.name,c.name',(identifier,))]
    for row in rows:
        row['fresh']=bool(row['enabled'] and row['at'] is not None and 0<=now-row['at']<=max(180,row['interval']*3))
        row['state']='down' if row['fresh'] and row['health']=='down' and row['latest_health']=='down' else 'healthy' if row['fresh'] and row['health']=='healthy' and row['latest_health']=='healthy' else 'unknown'
    state='down' if any(r['state']=='down' for r in rows) else 'healthy' if rows and all(r['state']=='healthy' for r in rows) else 'unknown'
    return state,rows


def view(store):
    with store.connect() as c:
        result=[]
        for row in c.execute('SELECT * FROM applications ORDER BY name').fetchall():
            state,checks=health(c,row['id'],time.time())
            deps=[dict(r) for r in c.execute('SELECT d.check_id,d.upstream_id,ch.name AS child,up.name AS upstream FROM application_dependencies d JOIN checks ch ON ch.id=d.check_id JOIN checks up ON up.id=d.upstream_id WHERE d.application_id=?',(row['id'],))]
            result.append({**dict(row),'health':state,'checks':checks,'dependencies':deps})
        return result


def context(c,machine,now):
    result=[]
    for row in c.execute('SELECT DISTINCT a.* FROM applications a JOIN application_checks ac ON ac.application_id=a.id JOIN checks ch ON ch.id=ac.check_id WHERE ch.machine_id=? ORDER BY a.name LIMIT 5',(machine,)).fetchall():
        state,checks=health(c,row['id'],now)
        result.append({'name':row['name'],'health':state,'checks':checks[:20],'dependencies':[dict(r) for r in c.execute('SELECT check_id,upstream_id FROM application_dependencies WHERE application_id=?',(row['id'],))],'note':'Explicit dependency relationship; concurrent failure is a troubleshooting lead, not proof of cause.'})
    return result


def upstream_incident(c,incident_id,now):
    """Only a currently failing, fresh upstream check can group downstream work."""
    row=c.execute('SELECT check_id FROM incidents WHERE id=?',(incident_id,)).fetchone()
    if not row:return None
    visited={row['check_id']};pending=[row['check_id']];candidate=None
    while pending:
        key=pending.pop()
        for dep in c.execute('SELECT upstream_id FROM application_dependencies WHERE check_id=?',(key,)).fetchall():
            parent=dep['upstream_id']
            if parent in visited:continue
            visited.add(parent)
            up=c.execute("SELECT i.id,c.health,c.enabled,c.interval,o.at,o.health AS latest_health FROM checks c JOIN incidents i ON i.check_id=c.id AND i.closed IS NULL AND i.status!='Resolved' LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE c.id=?",(parent,)).fetchone()
            if up and up['id']!=incident_id and up['enabled'] and up['health']=='down' and up['latest_health']=='down' and up['at'] is not None and 0<=now-up['at']<=max(180,up['interval']*3):
                candidate=up['id'];pending.append(parent)
    return candidate
