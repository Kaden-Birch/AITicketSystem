"""Plex diagnostics use a fixed read-only API surface, never arbitrary URLs."""
import json,re,time
import requests

class PlexError(ValueError):pass

def get(cfg,token,path,params=None,media=False):
    if not re.fullmatch(r'/(identity|status/sessions|library/sections|library/sections/[0-9]+/all|library/parts/[0-9]+/[0-9]+/file(?:\.[A-Za-z0-9]{1,10})?)',path):raise ValueError('Unsupported Plex diagnostic endpoint.')
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
    data['libraries']=[{'id':str(x['key']),'name':x.get('title','Library'),'type':x.get('type')} for x in sections[:100]]
    try:
        sessions=get(cfg,token,'/status/sessions').get('MediaContainer',{});items=sessions.get('Metadata',[])
        data['metrics'].update(active_sessions=sessions.get('size',len(items)),transcoding_sessions=sum('TranscodeSession' in x for x in items))
        # No viewing titles, usernames, client IPs or tokens are retained.
    except PlexError as exc:data['warnings'].append(str(exc))
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
