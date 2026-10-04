# Run in an elevated 64-bit PowerShell. State and command ledgers survive upgrades.
[CmdletBinding()]
param([string]$Server,[string]$CA,[string]$Source,[string]$PythonExe,[string]$Root="$env:ProgramData\AITicketAgent")
$ErrorActionPreference='Stop'
# Do not inherit PowerShell 7 modules when launching Windows PowerShell 5.1.
$env:PSModulePath="$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open PowerShell as Administrator.'}
if(![Environment]::Is64BitProcess){throw 'Use 64-bit PowerShell.'}
function Native([string]$Exe,[string[]]$Arguments){ & $Exe @Arguments; if($LASTEXITCODE -ne 0){throw "$Exe failed (exit $LASTEXITCODE)"} }
function Python([string]$Code,[string[]]$Parameters){
 $script=Join-Path $temp 'install-step.py'
 [IO.File]::WriteAllText($script,$Code)
 Native $PythonExe (@($script)+$Parameters)
}
New-Item -ItemType Directory -Force -Path $Root | Out-Null
# SYSTEM and local Administrators exclusively own code, policy, identity and logs.
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $Root -AclObject $acl
if(Get-ChildItem -LiteralPath $Root -Force){Native 'icacls.exe' @((Join-Path $Root '*'),'/reset','/T','/C')}
# Restore the exclusive root ACL after resetting existing children to inherited rules.
Set-Acl -LiteralPath $Root -AclObject $acl
foreach($dir in @('releases','state','config')){New-Item -ItemType Directory -Force -Path (Join-Path $Root $dir) | Out-Null}
$temp=Join-Path $Root ('install-'+[guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
 if(!$PythonExe){
  $PythonExe=Join-Path $Root 'runtime\python.exe'
  if(!(Test-Path -LiteralPath $PythonExe)){
   $archive=Join-Path $temp 'python.zip'
   Invoke-WebRequest -UseBasicParsing 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip' -OutFile $archive
   if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower() -ne '97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297'){throw 'Python runtime checksum failed.'}
   $runtime=Join-Path $Root 'runtime'
   Expand-Archive -LiteralPath $archive -DestinationPath $runtime -Force
   # Isolated application runtime: no Python registrations, shared install upgrades or PATH changes.
   [IO.File]::WriteAllText((Join-Path $runtime 'python313._pth'),"python313.zip`n.`nLib\site-packages`nimport site`n")

  }
  $pipPresent=$true
  try { Python 'import importlib.util; assert importlib.util.find_spec("pip") is not None' @() } catch { $pipPresent=$false }
  if(!$pipPresent){
   $bootstrap=Join-Path $temp 'get-pip.py'
   Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/pypa/get-pip/af54dfe793b24685f8dc4ebba0630d9f2d77653c/public/get-pip.py' -OutFile $bootstrap
   if((Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash.ToLower() -ne 'fb24e693bab954209a063d90953621412ccad4a500905a726286e038f508ddf6'){throw 'PyPA bootstrap checksum failed.'}
   Native $PythonExe @($bootstrap,'--disable-pip-version-check')
  }
 }
 Python 'import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32' @()
 Native $PythonExe @('-m','pip','install','--disable-pip-version-check','cryptography>=43,<47')
 if(!$Source){
  $archive=Join-Path $temp 'source.zip'
  Invoke-WebRequest -UseBasicParsing 'https://github.com/Kaden-Birch/AITicketSystem/archive/refs/heads/main.zip' -OutFile $archive
  Expand-Archive -LiteralPath $archive -DestinationPath $temp
  $Source=Join-Path $temp 'AITicketSystem-main'
 }
 $files=@('agent.py','commands.py','diagnostics.py','actions.py','monitoring.py','network.py','install_verify.py','windows/runner.py','windows/backend.py','windows/platform_support.py','windows/launcher.py','windows/updater.py','windows/install.ps1','release-public.pem')
 $sums=@{}
 Get-Content -LiteralPath (Join-Path $Source 'SHA256SUMS') | ForEach-Object { $parts=$_ -split '  ',2; $sums[$parts[1]]=$parts[0] }
 foreach($name in $files){
  $file=Join-Path $Source ('agent/'+$name)
  if(!(Test-Path -LiteralPath $file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower() -ne $sums['agent/'+$name]){throw "Source checksum mismatch: $name"}
 }
 foreach($task in @('AITicketAgentUpdater','AITicketAgent')){if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Stop-ScheduledTask -TaskName $task}}
 $bundle=Join-Path $Root ('releases\bootstrap-'+[guid]::NewGuid().ToString())
 New-Item -ItemType Directory -Path (Join-Path $bundle 'windows') -Force | Out-Null
 foreach($name in $files | Where-Object {$_ -notin @('windows/launcher.py','windows/updater.py','windows/install.ps1','release-public.pem')}){Copy-Item -LiteralPath (Join-Path $Source ('agent/'+$name)) -Destination (Join-Path $bundle $name)}
 Copy-Item -LiteralPath (Join-Path $Source 'agent/windows/launcher.py') -Destination (Join-Path $Root 'launcher.py')
 Copy-Item -LiteralPath (Join-Path $Source 'agent/windows/updater.py') -Destination (Join-Path $Root 'updater.py')
 Copy-Item -LiteralPath (Join-Path $Source 'agent/windows/platform_support.py') -Destination (Join-Path $Root 'platform_support.py')
 Copy-Item -LiteralPath (Join-Path $Source 'agent/release-public.pem') -Destination (Join-Path $Root 'release-public.pem')
 @{path=$bundle} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Root 'current.json')
 # Windows PowerShell 5.1 writes a BOM; normalize all generated JSON through Python.
 $policy=Join-Path $Root 'config\policy.json'
 Python 'import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);d=json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else {};d["commands"]={"enabled":True,"timeout":3600,"output_limit":65536,"sudo":False};p.write_text(json.dumps(d),encoding="utf-8")' @($policy)
 $updater=Join-Path $Root 'config\updater.json'
 if(!(Test-Path -LiteralPath $updater)){[IO.File]::WriteAllText($updater,'{"automatic":true}')}
 Python 'import pathlib,json,sys;p=pathlib.Path(sys.argv[1]);p.write_text(json.dumps(json.loads(p.read_text(encoding="utf-8-sig"))),encoding="utf-8")' @((Join-Path $Root 'current.json'))
 if(!(Test-Path -LiteralPath (Join-Path $Root 'state\identity.json'))){
  if(!$Server){$Server=Read-Host 'Main application URL'}
  $enroll=@((Join-Path $Root 'launcher.py'),'enroll','--server',$Server)
  if($Server.StartsWith('http://')){$enroll+='--allow-http'}
  if($CA){$enroll+=@('--ca',$CA)}
  Native $PythonExe $enroll
 }
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $action=New-ScheduledTaskAction -Execute $PythonExe -Argument ('"'+(Join-Path $Root 'launcher.py')+'" run') -WorkingDirectory $Root
 Register-ScheduledTask -TaskName 'AITicketAgent' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings -Force | Out-Null
 $updateAction=New-ScheduledTaskAction -Execute $PythonExe -Argument ('"'+(Join-Path $Root 'updater.py')+'"') -WorkingDirectory $Root
 $updateSettings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 5)
 Register-ScheduledTask -TaskName 'AITicketAgentUpdater' -Action $updateAction -Trigger $trigger -Principal $principal -Settings $updateSettings -Force | Out-Null
 Python 'import pathlib,re,json,sys;root=pathlib.Path(sys.argv[1]);bundle=pathlib.Path(json.loads((root/"current.json").read_text())["path"]);v=re.search(r"VERSION = .([^\x27]+).",(bundle/"agent.py").read_text()).group(1);(root/"state"/"update-status.json").write_text(json.dumps({"installed":v,"state":"available","detail":"Independent Windows updater installed."}))' @($Root)
 Start-ScheduledTask -TaskName 'AITicketAgent'
 Start-Sleep -Seconds 3
 foreach($task in @('AITicketAgent','AITicketAgentUpdater')){if((Get-ScheduledTask -TaskName $task).Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Task is not configured as SYSTEM.'}}
 if((Get-ScheduledTask -TaskName 'AITicketAgent').State -ne 'Running'){throw 'Agent task did not start; inspect state\agent.log.'}
 $acl=Get-Acl -LiteralPath $Root
 if(!$acl.AreAccessRulesProtected){throw 'Agent directory inheritance was not restricted.'}
 Write-Host 'Installed: LocalSystem agent, enabled command policy, protected state, independent automatic updater. Application host access mode controls commands.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
