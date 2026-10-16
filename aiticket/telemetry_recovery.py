"""Offline candidate construction. Never installs a database or opens the live DB.

.recover salvages only telemetry; all other rows and schema come from verified
reads of the working source. The protected original remains outside this tool.
"""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess


def quote(name):return '"'+name.replace('"','""')+'"'


def encoded(row):
    return json.dumps(list(row),ensure_ascii=True,separators=(',',':'),default=lambda x:{'blob_hex':bytes(x).hex()}).encode()


def read_rows(db,table):
    cols=db.execute('PRAGMA table_xinfo('+quote(table)+')').fetchall()
    if any(r[6] for r in cols):raise ValueError('Generated/hidden columns need a separate reviewed recovery procedure')
    try:db.execute('SELECT _rowid_ FROM '+quote(table)+' LIMIT 0')
    except sqlite3.OperationalError:
        pk=[r[1] for r in sorted(cols,key=lambda r:r[5]) if r[5]]
        return db.execute('SELECT * FROM '+quote(table)+' NOT INDEXED ORDER BY '+','.join(map(quote,pk))),[r[1] for r in cols],False
    return db.execute('SELECT _rowid_,* FROM '+quote(table)+' NOT INDEXED ORDER BY _rowid_'),['_rowid_']+[r[1] for r in cols],True


def digest_table(db,table):
    cursor,_,_=read_rows(db,table);digest=hashlib.sha256();count=0
    for row in cursor:
        blob=encoded(row);digest.update(len(blob).to_bytes(8,'big'));digest.update(blob);count+=1
    return {'rows':count,'sha256':digest.hexdigest()}


def usable(row):
    from .telemetry_archive import KINDS
    if not isinstance(row['payload'],str):return False
    try:payload=json.loads(row['payload'])
    except (ValueError,TypeError):return False
    return (isinstance(payload,dict) and isinstance(row['id'],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',row['id']) is not None
            and row['kind'] in KINDS and row['uploaded'] in (-1,0,1)
            and all(type(row[k]) in (int,float) and math.isfinite(row[k]) and row[k]>0 for k in ('at','received'))
            and type(row['size']) is int and row['size']>=128
            and all(row[k] is None or isinstance(row[k],str) and len(row[k])<=512 for k in ('entity_id','machine_id')))


def construct(source,output,salvage):
    src=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)
    saved=sqlite3.connect(salvage.as_uri()+'?mode=ro',uri=True);saved.row_factory=sqlite3.Row
    dst=sqlite3.connect(output)
    report={'source':str(source),'candidate':str(output),'protected_tables':{},'telemetry_recovered':0,'telemetry_rejected':0,'installed':False}
    try:
        schema=src.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY rowid").fetchall()
        tables=[r[1] for r in schema if r[0]=='table']
        if 'telemetry_records' not in tables:raise ValueError('Source does not contain the expected telemetry table')
        dst.execute('PRAGMA foreign_keys=OFF');dst.execute('BEGIN')
        for kind,name,table,sql in schema:
            if kind=='table':
                if sql.lstrip().upper().startswith('CREATE VIRTUAL'):raise ValueError('Virtual tables require separate review')
                dst.execute(sql)
        for table in tables:
            if table=='telemetry_records':continue
            rows,columns,_=read_rows(src,table)
            sql='INSERT INTO '+quote(table)+'('+','.join(map(quote,columns))+') VALUES('+','.join('?' for _ in columns)+')'
            while batch:=rows.fetchmany(500):dst.executemany(sql,batch)
            before=digest_table(src,table);after=digest_table(dst,table)
            if before!=after:raise ValueError('Protected table differs after copying: '+table)
            report['protected_tables'][table]=before
        columns=[r[1] for r in dst.execute('PRAGMA table_info(telemetry_records)')]
        rows=saved.execute('SELECT '+','.join(map(quote,columns))+' FROM telemetry_records NOT INDEXED')
        insert='INSERT INTO telemetry_records('+','.join(map(quote,columns))+') VALUES('+','.join('?' for _ in columns)+')'
        for row in rows:
            if not usable(row):report['telemetry_rejected']+=1;continue
            values=dict(row);values['size']=len(row['payload'].encode())+128
            try:dst.execute(insert,tuple(values[c] for c in columns))
            except sqlite3.IntegrityError:report['telemetry_rejected']+=1;continue
            report['telemetry_recovered']+=1
        # Only repair queue bookkeeping after copying the original metadata exactly.
        pending=dst.execute('SELECT coalesce(sum(size),0) FROM telemetry_records WHERE uploaded=0').fetchone()[0]
        dst.execute('UPDATE telemetry_archive_meta SET pending_bytes=? WHERE id=1',(pending,))
        dst.execute("UPDATE settings SET value='{}' WHERE key='telemetry_archive_batch'")
        report['queue_bookkeeping_recalculated']=True
        report['queue_checkpoint_reset']=True
        for kind,name,table,sql in schema:
            if kind!='table':dst.execute(sql)
        dst.commit()
        integrity=[r[0] for r in dst.execute('PRAGMA integrity_check')]
        report['integrity']=integrity
        if integrity!=['ok']:raise ValueError('Candidate failed integrity check')
        fk=dst.execute('PRAGMA foreign_key_check').fetchall();report['foreign_key_errors']=len(fk)
        if fk:raise ValueError('Candidate has foreign key errors')
        # Ensure every original schema object was restored, including protective triggers.
        actual=dst.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY rowid").fetchall()
        if sorted(schema)!=sorted(actual):raise ValueError('Candidate schema differs from source')
        for table in tables:
            if table in ('telemetry_records','telemetry_archive_meta','settings'):continue
            if digest_table(dst,table)!=report['protected_tables'][table]:raise ValueError('Protected records changed: '+table)
        report['ready_for_review']=True
        lost=saved.execute("SELECT 1 FROM sqlite_schema WHERE name='lost_and_found'").fetchone()
        report['lost_and_found_rows']=saved.execute('SELECT count(*) FROM lost_and_found').fetchone()[0] if lost else 0
        return report
    except Exception:
        dst.rollback();raise
    finally:src.close();saved.close();dst.close()


def recover(source,output,shell):
    source=Path(source).resolve();output=Path(output).resolve()
    if source==Path('/data/app.db') or output==Path('/data/app.db') or '/original/' in source.as_posix() or '/original/' in output.as_posix():raise ValueError('Use a disposable working copy, never the live or protected original database')
    if not source.is_file() or source==output or output.exists():raise ValueError('Source must exist and candidate must be a new, separate file')
    if not output.parent.is_dir():raise ValueError('Candidate directory does not exist')
    size=sum(p.stat().st_size for p in (source,Path(str(source)+'-wal')) if p.exists())
    if shutil.disk_usage(output.parent).free<size*4+256*1048576:raise ValueError('Insufficient free space for salvage, candidate and indexes')
    version=subprocess.check_output([shell,'-version'],text=True).split()[0]
    from .sqlite_runtime import patched
    if not patched(tuple(map(int,version.split('.')))):raise ValueError('A patched SQLite recovery shell is required')
    salvage=output.with_name(output.name+'.salvage')
    if salvage.exists():raise ValueError('Salvage file already exists; choose a new candidate name')
    log=output.with_name(output.name+'.recovery-errors.txt')
    print('Recovering into a separate salvage file; the live and protected databases are untouched.',flush=True)
    with log.open('xb') as errors:
        producer=subprocess.Popen([shell,'-readonly',str(source),'.recover --ignore-freelist'],stdout=subprocess.PIPE,stderr=errors)
        consumer=subprocess.Popen([shell,'-bail',str(salvage)],stdin=producer.stdout,stdout=errors,stderr=errors)
        producer.stdout.close()
        imported=consumer.wait();recovered=producer.wait()
    if recovered or imported:raise ValueError('SQLite salvage reported errors. Private diagnostic file: '+str(log))
    print('Building candidate; copying and verifying non-telemetry tables.',flush=True)
    report=construct(source,output,salvage)
    output.with_name(output.name+'.report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='protected_tables'},indent=2),flush=True)
    print('Non-telemetry table copies verified:',len(report['protected_tables']),flush=True)
    print('Candidate is NOT installed. Keep services stopped pending review.',flush=True)
    return report


def main():
    import os
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--sqlite',default='/opt/aiticket-sqlite/bin/sqlite3')
    args=parser.parse_args()
    try:recover(args.source,args.output,args.sqlite)
    except Exception as exc:raise SystemExit(type(exc).__name__+': '+str(exc))


if __name__=='__main__':main()
