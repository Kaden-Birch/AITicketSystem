"""Build the pinned, checksum-verified SQLite runtime and recovery shell for Linux."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION='3540000'
SHA3='f5e3e724e9c9b3b5d512c76b02082091a59eeea9becd169a9fbf4d376403acce'
prefix=Path('/opt/aiticket-sqlite')
with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary)
    with urllib.request.urlopen('https://www.sqlite.org/2026/sqlite-autoconf-'+VERSION+'.tar.gz',timeout=90) as response:
        data=response.read(8_000_001)
    if hashlib.sha3_256(data).hexdigest()!=SHA3:raise SystemExit('SQLite source checksum mismatch')
    archive=root/'source.tar.gz';archive.write_bytes(data)
    with tarfile.open(archive) as source:source.extractall(root,filter='data')
    source=root/('sqlite-autoconf-'+VERSION)
    flags=['-O2','-fPIC','-DSQLITE_THREADSAFE=1','-DSQLITE_ENABLE_COLUMN_METADATA','-DSQLITE_ENABLE_SESSION','-DSQLITE_ENABLE_PREUPDATE_HOOK','-DSQLITE_ENABLE_FTS5','-DSQLITE_ENABLE_RTREE','-DSQLITE_ENABLE_DBSTAT_VTAB','-DSQLITE_ENABLE_DBPAGE_VTAB']
    cc=os.environ.get('CC','cc')
    subprocess.run([cc,*flags,'-c','sqlite3.c','-o','sqlite3.o'],cwd=source,check=True)
    (prefix/'lib').mkdir(parents=True);(prefix/'bin').mkdir()
    subprocess.run([cc,'-shared','-Wl,-soname,libsqlite3.so.0','sqlite3.o','-lm','-ldl','-pthread','-o',str(prefix/'lib/libsqlite3.so.0')],cwd=source,check=True)
    (prefix/'lib/libsqlite3.so').symlink_to('libsqlite3.so.0')
    subprocess.run([cc,*flags,'shell.c','sqlite3.o','-lm','-ldl','-pthread','-o',str(prefix/'bin/sqlite3')],cwd=source,check=True)
    version=subprocess.check_output([str(prefix/'bin/sqlite3'),'-version'],text=True)
    if not version.startswith('3.54.0 '):raise SystemExit('Unexpected SQLite runtime version')
    help_text=subprocess.check_output([str(prefix/'bin/sqlite3'),':memory:','.help recover'],text=True)
    if '.recover' not in help_text:raise SystemExit('SQLite recovery shell is unavailable')
    print(version.strip())
