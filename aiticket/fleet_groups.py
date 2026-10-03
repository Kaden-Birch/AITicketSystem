"""Dynamic inventory selections and independent, many-to-many Fleet groups."""
import json,re
from .db import uid


def hosts(store):
    return store.rows("SELECT * FROM machines WHERE id NOT LIKE 'unifi:%' AND id NOT LIKE 'unifi-device:%' ORDER BY name")


def catalog(store):
    machines=hosts(store);ids={m['id'] for m in machines}
    agents=store.rows('SELECT machine_id,host_info FROM agents WHERE revoked=0')
    linux=[];windows=[];enrolled=[]
    for agent in agents:
        if agent['machine_id'] not in ids:continue
        enrolled.append(agent['machine_id'])
        info=json.loads(agent['host_info'] or '{}')
        os_name=' '.join(str(info.get(k,'')) for k in ('os','system','platform')).lower()
        if re.search(r'\b(windows|win32|win64)\b',os_name):windows.append(agent['machine_id'])
        elif re.search(r'\b(linux|ubuntu|debian|proxmox|fedora|centos|rocky|almalinux|arch|suse|opensuse|raspbian|raspberry pi|mint|gentoo|alpine|nixos|kali|rhel|red hat)\b',os_name):linux.append(agent['machine_id'])
    nodes=store.rows("SELECT DISTINCT machine_id FROM proxmox_objects WHERE present=1 AND machine_id IS NOT NULL AND kind='node'")
    guests=store.rows("SELECT DISTINCT machine_id FROM proxmox_objects WHERE present=1 AND machine_id IS NOT NULL AND kind IN ('qemu','lxc')")
    builtins=[{'id':'builtin:'+key,'name':name,'members':sorted(set(members)&ids)} for key,name,members in (
        ('agents','All enrolled agents',enrolled),('linux','Linux agents',linux),('windows','Windows agents',windows),
        ('proxmox','Proxmox nodes',[r['machine_id'] for r in nodes]),('guests','Proxmox VMs & containers',[r['machine_id'] for r in guests]),
        ('no-agent','Hosts without an agent',ids-set(enrolled)))]
    custom=store.rows('SELECT * FROM fleet_groups ORDER BY name COLLATE NOCASE')
    memberships=store.rows('SELECT * FROM fleet_group_members')
    for group in custom:
        group['members']=sorted(r['machine_id'] for r in memberships if r['group_id']==group['id'] and r['machine_id'] in ids)
    notifications=store.rows('SELECT * FROM notification_groups ORDER BY name')
    membership=store.rows('SELECT * FROM machine_groups')
    notification_options=[{'id':'notification:'+g['id'],'name':g['name'],'members':sorted(r['machine_id'] for r in membership if r['group_id']==g['id'] and r['machine_id'] in ids)} for g in notifications]
    categories=[{'label':'Built-in groups','groups':builtins},{'label':'Custom groups','groups':[{**g,'id':'custom:'+g['id']} for g in custom]}]
    if notification_options:categories.append({'label':'Notification groups','groups':notification_options})
    return {'machines':machines,'categories':categories,'custom_groups':custom}


def save(store,name,members,identifier=None):
    name=name.strip()
    if not name or len(name)>100:raise ValueError('Give the group a name between 1 and 100 characters.')
    members=list(dict.fromkeys(members))
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if identifier and not c.execute('SELECT id FROM fleet_groups WHERE id=?',(identifier,)).fetchone():raise ValueError('This Fleet group no longer exists.')
        if c.execute('SELECT id FROM fleet_groups WHERE name=? COLLATE NOCASE AND id<>?',(name,identifier or '')).fetchone():raise ValueError('A Fleet group with this name already exists. Choose another name.')
        allowed={m['id'] for m in hosts(store)}
        if not set(members)<=allowed:raise ValueError('Choose existing hosts, not network devices.')
        created=identifier is None;identifier=identifier or uid()
        if created:c.execute('INSERT INTO fleet_groups VALUES(?,?)',(identifier,name))
        else:c.execute('UPDATE fleet_groups SET name=? WHERE id=?',(name,identifier))
        c.execute('DELETE FROM fleet_group_members WHERE group_id=?',(identifier,))
        c.executemany('INSERT INTO fleet_group_members VALUES(?,?)',[(identifier,m) for m in members])
        store.audit(c,'fleet.group_created' if created else 'fleet.group_updated',identifier,{'name':name,'hosts':len(members)})
    return identifier


def delete(store,identifier):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('DELETE FROM fleet_groups WHERE id=?',(identifier,)).rowcount:raise ValueError('This Fleet group no longer exists.')
        store.audit(c,'fleet.group_deleted',identifier)
