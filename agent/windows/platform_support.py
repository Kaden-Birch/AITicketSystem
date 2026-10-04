"""Windows primitives shared by the agent and independent updater; no agent imports."""
import base64,ctypes,json,os,subprocess,threading,time
from pathlib import Path
from ctypes import wintypes

class OVERLAPPED(ctypes.Structure):
    _fields_=[('Internal',ctypes.c_size_t),('InternalHigh',ctypes.c_size_t),('Offset',wintypes.DWORD),('OffsetHigh',wintypes.DWORD),('hEvent',wintypes.HANDLE)]

class locks:
    LOCK_SH=1;LOCK_EX=2;LOCK_NB=4
    @staticmethod
    def flock(file,flags):
        import msvcrt
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.LockFileEx.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(OVERLAPPED)]
        kernel.LockFileEx.restype=wintypes.BOOL
        overlapped=OVERLAPPED()
        options=(2 if flags&locks.LOCK_EX else 0)|(1 if flags&locks.LOCK_NB else 0)
        if not kernel.LockFileEx(msvcrt.get_osfhandle(file.fileno()),options,0,1,0,ctypes.byref(overlapped)):
            code=ctypes.get_last_error()
            if code in (33,158):raise BlockingIOError('Agent work is active')
            raise ctypes.WinError(code)


def system_directory():
    buffer=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer)):raise ctypes.WinError()
    return Path(buffer.value)


def powershell():return str(system_directory()/'WindowsPowerShell'/'v1.0'/'powershell.exe')


def ps_argv(script):
    code="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"+script
    return [powershell(),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()]


def literal(value):return "'"+str(value).replace("'","''")+"'"


class BASIC_LIMIT(ctypes.Structure):
    _fields_=[('PerProcessUserTimeLimit',ctypes.c_longlong),('PerJobUserTimeLimit',ctypes.c_longlong),('LimitFlags',wintypes.DWORD),('MinimumWorkingSetSize',ctypes.c_size_t),('MaximumWorkingSetSize',ctypes.c_size_t),('ActiveProcessLimit',wintypes.DWORD),('Affinity',ctypes.c_size_t),('PriorityClass',wintypes.DWORD),('SchedulingClass',wintypes.DWORD)]
class IO_COUNTERS(ctypes.Structure):
    _fields_=[(name,ctypes.c_ulonglong) for name in ('ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
class EXTENDED_LIMIT(ctypes.Structure):
    _fields_=[('BasicLimitInformation',BASIC_LIMIT),('IoInfo',IO_COUNTERS),('ProcessMemoryLimit',ctypes.c_size_t),('JobMemoryLimit',ctypes.c_size_t),('PeakProcessMemoryUsed',ctypes.c_size_t),('PeakJobMemoryUsed',ctypes.c_size_t)]


class Job:
    """Kill the entire command process tree when its job handle is closed."""
    def __init__(self,process):
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];self.kernel.CreateJobObjectW.restype=wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        self.handle=self.kernel.CreateJobObjectW(None,None)
        settings=EXTENDED_LIMIT();settings.BasicLimitInformation.LimitFlags=0x2000
        if not self.handle or not self.kernel.SetInformationJobObject(self.handle,9,ctypes.byref(settings),ctypes.sizeof(settings)) or not self.kernel.AssignProcessToJobObject(self.handle,int(process._handle)):
            error=ctypes.get_last_error();self.close();process.kill();process.wait(timeout=5);raise ctypes.WinError(error)
    def close(self):
        if self.handle:self.kernel.CloseHandle(self.handle);self.handle=None


class THREAD_ENTRY(ctypes.Structure):
    _fields_=[('dwSize',wintypes.DWORD),('cntUsage',wintypes.DWORD),('th32ThreadID',wintypes.DWORD),('th32OwnerProcessID',wintypes.DWORD),('tpBasePri',ctypes.c_long),('tpDeltaPri',ctypes.c_long),('dwFlags',wintypes.DWORD)]


def resume(pid):
    # Assign the suspended process to its job before it can create any children.
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD];k.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
    k.Thread32First.argtypes=[wintypes.HANDLE,ctypes.POINTER(THREAD_ENTRY)];k.Thread32Next.argtypes=k.Thread32First.argtypes
    k.OpenThread.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenThread.restype=wintypes.HANDLE
    k.ResumeThread.argtypes=[wintypes.HANDLE];k.ResumeThread.restype=wintypes.DWORD;k.CloseHandle.argtypes=[wintypes.HANDLE]
    snapshot=k.CreateToolhelp32Snapshot(4,0);entry=THREAD_ENTRY();entry.dwSize=ctypes.sizeof(entry)
    if snapshot in (None,ctypes.c_void_p(-1).value):raise ctypes.WinError(ctypes.get_last_error())
    try:
        more=k.Thread32First(snapshot,ctypes.byref(entry))
        while more:
            if entry.th32OwnerProcessID==pid:
                thread=k.OpenThread(2,False,entry.th32ThreadID)
                if not thread:raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if k.ResumeThread(thread)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
                finally:k.CloseHandle(thread)
                return
            more=k.Thread32Next(snapshot,ctypes.byref(entry))
        raise ValueError('Suspended command thread unavailable')
    finally:k.CloseHandle(snapshot)


def run(argv,timeout=5,limit=16000,allowed=None):
    """Bounded concurrent pipe draining; Windows pipes do not support selectors."""
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000004)
    job=Job(process)
    try:resume(process.pid)
    except Exception:
        job.close();process.wait(timeout=5);raise
    buffers={'stdout':bytearray(),'stderr':bytearray()};mutex=threading.Lock();truncated=False
    def reader(stream,name):
        nonlocal truncated
        try:
            while True:
                data=stream.read(4096)
                if not data:break
                with mutex:
                    remaining=max(0,limit-sum(len(b) for b in buffers.values()));buffers[name].extend(data[:remaining]);truncated=truncated or len(data)>remaining
        finally:stream.close()
    threads=[threading.Thread(target=reader,args=(stream,name),daemon=True) for stream,name in ((process.stdout,'stdout'),(process.stderr,'stderr'))]
    for t in threads:t.start()
    deadline=time.monotonic()+timeout;next_check=0;state=None
    try:
        while process.poll() is None:
            now=time.monotonic()
            if now>=deadline:state='unknown';break
            if allowed and now>=next_check:
                try:permission=allowed()
                except Exception:permission=False
                if not permission:state='cancelled';break
                next_check=now+2
            time.sleep(.1)
    finally:
        job.close()
    code=process.wait(timeout=5)
    for t in threads:t.join(timeout=2)
    output={};remaining=limit
    for name in ('stdout','stderr'):
        encoded=buffers[name].decode('utf-8','replace').encode('utf-8');output[name]=encoded[:remaining].decode('utf-8','ignore');remaining-=len(output[name].encode('utf-8'))
    return {'state':state or ('completed' if code==0 else 'failed'),'exit_code':code,**output,'truncated':truncated}


def ps(script,timeout=8,limit=16000):
    result=run(ps_argv(script),timeout,limit)
    if result['state']!='completed' or result['truncated']:raise ValueError('Windows query unavailable or exceeded its bounds')
    return result['stdout'].strip()


def query(script,timeout=8,limit=16000):return json.loads(ps(script+' | ConvertTo-Json -Compress -Depth 6',timeout,limit) or 'null')


def policy(path):
    p=Path(path)
    return json.loads(p.read_text()) if p.exists() else {}


def activate(root,target):
    p=Path(root)/'current.json';tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps({'path':str(Path(target).resolve())}));os.replace(tmp,p)


def current(root):
    root=Path(root).resolve();path=Path(json.loads((root/'current.json').read_text())['path']).resolve()
    if path.parent!=root/'releases':raise ValueError('Invalid active release path')
    return path
