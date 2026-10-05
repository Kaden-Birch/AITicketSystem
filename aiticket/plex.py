"""Plex diagnostics use a fixed read-only API surface, never arbitrary URLs."""
import json,re,time,hashlib
import requests

class PlexError(ValueError):pass

def get(cfg,token,path,params=None,media=False):
    if not re.fullmatch(r'/(identity|status/sessions|library/sections|library/sections/[0-9]+/all|library/parts/[0-9]+(?:/[0-9]+)?/file(?:\.[A-Za-z0-9]{1,10})?)',path):raise ValueError('Unsupported Plex diagnostic endpoint.')
    headers={'Accept':'application/json','X-Plex-Token':token,'X-Plex-Client-Identifier':'aiticket-monitor','X-Plex-Product':'AITicketSystem'}
    if media:headers['Range']='bytes=0-0'
    response=requests.get(cfg['url']+path,headers=headers,params=params,timeout=(3,8),verify=cfg.get('ca',True),allow_redirects=False,stream=True)
    try:
        if response.status_code in (401,403):raise PlexError('Plex rejected the token. Check its server access.')
        if response.status_code>=400:
            if media and response.status_code in (404,500,503):return False
            raise PlexError('Plex could not provide this reading. HTTP '+str(response.status_code)+'.')
        if media:
            if response.status_code!=206 or not re.fullmatch(r'bytes 0-0/[1-9][0-9]*',response.headers.get('Content-Range','')):raise PlexError('Plex did not confirm a one-byte media read. Storage access is unverified.')
            return len(next(response.iter_content(chunk_size=1),b''))==1
        if response.status_code!=200:raise PlexError('Plex redirected or returned an unexpected response. Use its direct server address.')
        body=bytearray()
        for chunk in response.iter_content(65536):
            body.extend(chunk)
            if len(body)>1_000_000:raise PlexError('Plex returned too much data. Reading remains unverified.')
        return json.loads(body)
    finally:response.close()


def collect(cfg,token):
    begin=time.monotonic()
    try:identity=get(cfg,token,'/identity').get('MediaContainer',{})
    except (requests.exceptions.ConnectionError,requests.exceptions.Timeout) as exc:
        if isinstance(exc,requests.exceptions.SSLError):raise
        return {'responsive':False,'media_access':None,'media_reason':'Plex is not responding.','libraries':[],'metrics':{},'warnings':[]}
    if not identity.get('machineIdentifier') or not identity.get('version'):raise PlexError('The address did not return a valid Plex server identity.')
    data={'responsive':True,'version':identity.get('version'),'metrics':{'response_ms':round((time.monotonic()-begin)*1000,1)},'libraries':[],'media_access':None,'media_reason':'Choose a media library to verify file access.','warnings':[]}
    sections=get(cfg,token,'/library/sections').get('MediaContainer',{}).get('Directory',[])
    data['libraries']=[{'id':str(x['key']),'name':x.get('title','Library'),'type':x.get('type'),'locations_count':len(x.get('Location',[])),'locations':[{'id':str(loc.get('id','')),'path':str(loc.get('path',''))[:1000]} for loc in x.get('Location',[])[:20]]} for x in sections[:100]]
    try:
        sessions=get(cfg,token,'/status/sessions').get('MediaContainer',{});items=sessions.get('Metadata',[])
        data['metrics'].update(active_sessions=sessions.get('size',len(items)),transcoding_sessions=sum('TranscodeSession' in x for x in items))
        reported=[x.get('TranscodeSession',{}).get('error') for x in items if isinstance(x.get('TranscodeSession'),dict)]
        flags=[error_flag(x) for x in reported]
        data['playback']={'transcode_errors':sum(x is True for x in flags),'error_reporting_available':any(x is True for x in flags) or not reported or all(x is not None for x in flags),'sessions_without_error_field':sum(x is None for x in flags),'coverage':'Only errors explicitly reported by currently active transcode sessions. Finished or client-only playback failures are not exposed by this reading.'}
        if data['playback']['error_reporting_available']:data['metrics']['transcode_errors']=data['playback']['transcode_errors']
        # No viewing titles, usernames, client IPs or tokens are retained.
    except PlexError as exc:data['warnings'].append(str(exc))
    if cfg.get('deep_monitoring'):
        location_readings(data,cfg,token,begin)
        return data
    library=cfg.get('library_id')
    if library:
        try:
            container=get(cfg,token,'/library/sections/'+library+'/all',{'type':1 if next((x['type'] for x in data['libraries'] if x['id']==library),None)=='movie' else 4 if next((x['type'] for x in data['libraries'] if x['id']==library),None)=='show' else 10,'X-Plex-Container-Start':0,'X-Plex-Container-Size':1}).get('MediaContainer',{})
            items=container.get('Metadata',[]);parts=[p for i in items for m in i.get('Media',[]) for p in m.get('Part',[])]
            if not parts:raise PlexError('No sample media file is available in this library. Storage access is unverified.')
            key=parts[0].get('key','')
            data['media_access']=get(cfg,token,key,media=True)
            data['media_reason']='Plex read a sample file successfully.' if data['media_access'] else 'Plex could not read a sample file from this library. Check its storage mount and permissions.'
        except (PlexError,ValueError) as exc:data['media_reason']=str(exc)
    return data


def error_flag(value):
    if type(value) is bool:return value
    if type(value) in (int,float) and value in (0,1):return bool(value)
    if isinstance(value,str) and value.lower() in ('true','false','0','1'):return value.lower() in ('true','1')
    return None


def inside(file,path):
    # Windows paths are case-insensitive; boundary checks prevent /media matching /media-old.
    file=str(file).replace('\\','/');path=path.replace('\\','/').rstrip('/')
    if re.match(r'^[A-Za-z]:/',path):file=file.casefold();path=path.casefold()
    return bool(path) and file.startswith(path+'/')


def location_readings(data,cfg,token,begin):
    selected=cfg.get('library_ids') or ([cfg['library_id']] if cfg.get('library_id') else [])
    selected=selected[:10]
    previous={x['id']:x for x in cfg.get('_previous',{}).get('media_locations',[]) if isinstance(x,dict) and 'id' in x}
    data['media_locations']=[];data['coverage']={'selected_libraries':len(selected),'sample_limit_per_library':100,'location_limit':20,'note':'One sample per location; empty or unexamined locations remain unverified. Files are not exhaustively scanned.'}
    for library in data['libraries']:
        if library['id'] not in selected:continue
        locations=library.get('locations',[])
        if not locations:
            data['media_locations'].append({'id':library['id']+':unknown','library':library['name'],'path':'Location unavailable','readable':None,'reason':'Plex did not expose a media location for this library.'})
            continue
        candidates=[];todo=[]
        for loc in locations:
            if len(data['media_locations'])>=20:break
            identifier=library['id']+':'+(loc['id'] or hashlib.sha256(loc['path'].encode()).hexdigest()[:16])
            item={'id':identifier,'library':library['name'],'path':loc['path'],'readable':None,'reason':'No sample found yet. Up to 100 indexed items are searched per refresh.'}
            data['media_locations'].append(item);old=previous.get(identifier,{})
            if old.get('path')==loc['path'] and old.get('sample_key'):item['sample_key']=old['sample_key']
            else:todo.append(item)
            candidates.append(item)
        try:
            if todo and time.monotonic()-begin<50:
                cursor=cfg.get('_previous',{}).get('scan_cursors',{}).get(library['id'],0)
                cursor=cursor if type(cursor) is int and 0<=cursor<=1000000 else 0
                container=get(cfg,token,'/library/sections/'+library['id']+'/all',{'type':1 if library['type']=='movie' else 4 if library['type']=='show' else 13 if library['type']=='photo' else 10,'X-Plex-Container-Start':cursor,'X-Plex-Container-Size':100}).get('MediaContainer',{})
                items=container.get('Metadata',[])[:100]
                data.setdefault('scan_cursors',{})[library['id']]=cursor+len(items) if len(items)==100 else 0
                for obj in items:
                    for media in obj.get('Media',[])[:10]:
                        for part in media.get('Part',[])[:10]:
                            for item in todo:
                                if not item.get('sample_key') and inside(part.get('file',''),item['path']):item['sample_key']=part.get('key','')
            for item in candidates:
                if time.monotonic()-begin>=50:item['reason']='Collection budget reached. This location remains unverified.';continue
                if not item.get('sample_key'):continue
                try:
                    item['readable']=get(cfg,token,item['sample_key'],media=True)
                    item['reason']='Sample file readable.' if item['readable'] else 'Sample file unavailable. Check this mount and its permissions.'
                    if item['readable'] is False:item.pop('sample_key',None)
                except (PlexError,ValueError,requests.exceptions.RequestException):item['reason']='Sample read could not be confirmed. Check the connection and permissions.';item.pop('sample_key',None)
        except (PlexError,ValueError,requests.exceptions.RequestException):
            for item in todo:item['reason']='Library samples could not be retrieved. Access remains unverified.'
    known={x['id'] for x in data['libraries']}
    for library in selected:
        if library not in known and len(data['media_locations'])<20:data['media_locations'].append({'id':library+':missing','library':'Removed library','path':'Unavailable','readable':False,'reason':'The selected library is no longer exposed by Plex.'})
    if sum(x.get('locations_count',len(x.get('locations',[]))) or 1 for x in data['libraries'] if x['id'] in selected)>20:data['warnings'].append('Only the first 20 media locations are sampled per refresh. Remaining locations are unverified.')
    values=[x['readable'] for x in data['media_locations']]
    data['media_access']=False if False in values else True if values and all(x is True for x in values) and len(selected)<=10 and sum(x.get('locations_count',len(x.get('locations',[]))) or 1 for x in data['libraries'] if x['id'] in selected)<=20 else None
    readable=sum(x is True for x in values)
    data['media_reason']=str(readable)+' of '+str(len(values))+' sampled locations readable.' if values else 'Choose libraries in settings to check their media locations.'
