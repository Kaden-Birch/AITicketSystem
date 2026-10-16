"""Fail before opening a container database if the patched runtime was not loaded."""
import os
import sqlite3


def patched(version):
    return version>=(3,51,3) or (3,50,7)<=version<(3,51,0) or (3,44,6)<=version<(3,45,0)


def require_patched():
    if os.environ.get('AITICKET_REQUIRE_PATCHED_SQLITE')=='1' and not patched(sqlite3.sqlite_version_info):
        raise RuntimeError('SQLite runtime lacks the required upstream WAL-reset fix. Rebuild the application image before starting writers.')
