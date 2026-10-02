"""Three host access modes; only recognized read operations bypass approval."""
import re
import shlex
from pathlib import PurePosixPath

MODES={'readonly':'Read only commands','guarded':'Ask before potentially dangerous commands','immediate':'Full access'}


def read_only(command):
    # Unknown shell syntax or executables are changes for policy purposes.
    if any(x in command for x in ('$','`','\\','\n','\r','>','<','(',')','{','}')): return False
    try:
        lexer=shlex.shlex(command,posix=True,punctuation_chars=';&|');lexer.whitespace_split=True;lexer.commenters=''
        tokens=list(lexer)
    except ValueError: return False
    groups=[];current=[]
    for token in tokens:
        if token in (';','&&','||','|'):
            if not current: return False
            groups.append(current);current=[]
        elif token in ('&',';;',';&','|&'): return False
        else: current.append(token)
    if current: groups.append(current)
    if not groups: return False
    return all(read_segment(g) for g in groups)


def read_segment(args):
    if args[0]=='sudo':
        args=args[1:]
        if args and args[0]=='-n': args=args[1:]
        if args and args[0]=='--': args=args[1:]
        if not args: return False
    executable=PurePosixPath(args[0])
    if '/' in args[0] and str(executable.parent) not in ('/bin','/usr/bin','/sbin','/usr/sbin'): return False
    name=executable.name;args=args[1:]
    if any(x.startswith('-') and x in ('--help',) for x in args): return False
    if name in ('id','uptime','uname','df','free','ps','lsblk','lscpu','ls','stat','du','whoami','date'):
        if name=='date': return not any(x.startswith(('-s','--set','-f','--file')) for x in args) and not any(not x.startswith(('-','+')) for x in args)
        return True
    if name=='hostname': return all(x in ('-I','-i','-f','-s','-d','-A','--all-ip-addresses','--ip-address','--fqdn','--short','--domain','--all-fqdns') for x in args)
    if name=='ip':
        while args and args[0] in ('-brief','-br','-j','-json','-4','-6','-o','-s'): args=args[1:]
        if not args or args[0] not in ('address','addr','a','route','r','link','neighbor','neigh'): return False
        return len(args)==1 or args[1] in ('show','list','get')
    if name=='ss': return all(re.fullmatch(r'-[lntupaeo]+',x) or x in ('--listening','--numeric','--tcp','--udp','--processes') for x in args)
    if name=='systemctl':
        args=[x for x in args if x not in ('--no-pager','--failed','--all','--plain','--full','--no-legend')]
        if not args: return True
        if args[0] not in ('status','show','is-active','is-failed','list-units','list-unit-files'): return False
        return all(not x.startswith('-') or x.startswith(('--type=','--state=','--property=')) or x in ('--value',) for x in args[1:])
    if name=='journalctl':
        value_flags=('-n','--lines','-p','--priority','-u','--unit','--since','--until','-b','--boot')
        switches=('--no-pager','-k','--dmesg','--utc','--no-hostname','--disk-usage')
        i=0
        while i<len(args):
            x=args[i]
            if x in switches: i+=1
            elif x in value_flags and i+1<len(args): i+=2
            elif any(x.startswith(flag+'=') for flag in value_flags if flag.startswith('--')): i+=1
            else: return False
        return True
    if name=='cat': return bool(args) and all(x.startswith(('/proc/','/sys/')) or x=='/etc/os-release' for x in args)
    if name=='vmstat': return all(x.isdigit() and int(x)<=60 or x in ('-s','-d','-w','-t') for x in args)
    return False


def requires_approval(mode,command=None,method=None):
    read=method=='GET' if method is not None else read_only(command or '')
    if mode=='readonly' and not read: raise ValueError('This host allows read-only commands. Select Full access or the approval mode in Host settings to allow this operation.')
    if mode in ('readonly','immediate'): return False
    return mode=='required' or not read
