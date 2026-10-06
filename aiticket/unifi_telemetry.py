"""Join Integration API configuration and statistics without losing interfaces.

Radio statistics identify bands, not array positions. Duplicate bands are left
unmatched rather than attributing one radio's readings to another radio.
"""
from .unifi_nas_view import number


def mapping(value):
    return value if isinstance(value,dict) else {}


def percent(value):
    value=number(value)
    return value if value is not None and 0<=value<=100 else None


def radios(device,statistics):
    details=mapping(mapping(device).get('interfaces')).get('radios',[])
    readings=mapping(mapping(statistics).get('interfaces')).get('radios',[])
    details=[r for r in details[:100] if isinstance(r,dict)] if isinstance(details,list) else []
    readings=[r for r in readings[:100] if isinstance(r,dict)] if isinstance(readings,list) else []
    result=[]
    bands=[number(r.get('frequencyGHz')) for r in details]
    for row in details:
        band=number(row.get('frequencyGHz'))
        matches=[r for r in readings if band is not None and number(r.get('frequencyGHz'))==band]
        stats=matches[0] if len(matches)==1 and bands.count(band)==1 else {}
        radio={**row}
        # Retries are not airtime. Accept utilization only when explicitly reported.
        radio['txRetriesPct']=percent(stats.get('txRetriesPct',row.get('txRetriesPct')))
        radio['airtimePct']=percent(stats.get('airtimePct',stats.get('utilizationPct',row.get('airtimePct',row.get('utilizationPct')))))
        result.append(radio)
    # Preserve metrics-only radios when configuration could not be fetched.
    for row in readings:
        band=number(row.get('frequencyGHz'))
        if band is not None and band not in bands and sum(number(r.get('frequencyGHz'))==band for r in readings)==1:
            result.append({'frequencyGHz':band,'txRetriesPct':percent(row.get('txRetriesPct')),'airtimePct':percent(row.get('airtimePct',row.get('utilizationPct')))})
    return result


def combined(device,statistics):
    device=mapping(device);statistics=mapping(statistics)
    # Statistics interfaces/uplink are partial objects, never replacements.
    result={**device,**{k:v for k,v in statistics.items() if k not in ('interfaces','uplink')}}
    result['interfaces']={**mapping(device.get('interfaces')),'radios':radios(device,statistics)}
    result['uplink']={**mapping(device.get('uplink')),**mapping(statistics.get('uplink'))}
    return result


def radio_metrics(readings):
    rows=radios(readings.get('device'),readings.get('statistics'));values={}
    for radio in rows:
        band=number(radio.get('frequencyGHz'))
        if band is None or sum(number(r.get('frequencyGHz'))==band for r in rows)!=1:continue
        for metric in ('txRetriesPct','airtimePct'):
            value=radio[metric]
            if value is not None:values[f'radio.{band:g}.{metric}']=value
    return values
