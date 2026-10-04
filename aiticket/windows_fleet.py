"""Reviewed Windows fleet tasks; never distribute private SSH keys."""
import base64,json,re
from .fleet import name


def command(store,values):
    kind=values.get('kind')
    if kind=='script':
        script=values.get('script','')
        if not script.strip() or len(script)>14000:raise ValueError('Script must contain 1–14000 characters.')
        return script
    if kind=='packages':
        packages=values.get('packages','').split()
        if not packages or any(not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,100}',p) for p in packages):raise ValueError('Provide package IDs separated by spaces.')
        return "$ErrorActionPreference='Stop';if(!(Get-Command choco.exe -ErrorAction SilentlyContinue)){throw 'Install Chocolatey on this host first'}; choco.exe install "+' '.join(packages)+" --yes --no-progress; if($LASTEXITCODE -ne 0){throw 'Package installation failed'}"
    if kind not in ('user','key','revoke'):raise ValueError('Choose a fleet task.')
    user=name(values.get('username',''));groups=[name(g.strip()) for g in values.get('groups','').split(',') if g.strip()] if kind=='user' else []
    access=values.get('access','standard')
    if access not in ('standard','administrator'):raise ValueError('Choose standard or administrator access.')
    public=None
    if values.get('key_id'):
        rows=store.rows('SELECT public FROM fleet_keys WHERE id=?',(values['key_id'],))
        if not rows:raise ValueError('Unknown SSH key.')
        public=rows[0]['public']
    if kind in ('key','revoke') and not public:raise ValueError('Select an SSH key.')
    payload=base64.b64encode(json.dumps({'kind':kind,'user':user,'groups':groups,'administrator':access=='administrator','public':public}).encode()).decode()
    return "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+payload+"')) | ConvertFrom-Json;\n"+SCRIPT


SCRIPT=r'''$ErrorActionPreference='Stop'
$admin=Get-LocalGroup -SID 'S-1-5-32-544'
$user=Get-LocalUser -Name $p.user -ErrorAction SilentlyContinue
$groups=@($p.groups | ForEach-Object {Get-LocalGroup -Name $_})
$becomesAdmin=$p.administrator -or @($groups | Where-Object {$_.SID.Value -eq 'S-1-5-32-544'}).Count -gt 0
if($p.public -and (($p.kind -eq 'user' -and $becomesAdmin) -or ($user -and @(Get-LocalGroupMember -Group $admin.Name | Where-Object {$_.SID.Value -eq $user.SID.Value}).Count))){throw 'Windows OpenSSH shares administrator keys across accounts. Use a standard account for per-user key deployment; no shared administrator key file was changed.'}
if($p.kind -eq 'user'){
 if($user){throw 'Account already exists; preserved without modification'}
 $user=New-LocalUser -Name $p.user -NoPassword
 Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
 foreach($g in $p.groups){Add-LocalGroupMember -Group $g -Member $user}
 if($p.administrator){Add-LocalGroupMember -Group $admin.Name -Member $user}
}elseif(!$user){throw 'Account does not exist'}
if($p.public){
 $sid=$user.SID.Value
 $profile=Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$sid) -ErrorAction SilentlyContinue
 if(!$profile){
  Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public class FleetProfile{[DllImport("userenv.dll",CharSet=CharSet.Unicode)]public static extern int CreateProfile(string sid,string name,StringBuilder path,uint length);}'
  $path=[Text.StringBuilder]::new(260)
  $profileResult=[FleetProfile]::CreateProfile($sid,$p.user,$path,260)
  if($profileResult -ne 0){[Runtime.InteropServices.Marshal]::ThrowExceptionForHR($profileResult)}
  $profilePath=$path.ToString()
 }else{$profilePath=[Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath)}
 $directory=Join-Path $profilePath '.ssh';$file=Join-Path $directory 'authorized_keys'
 foreach($path in @($profilePath,$directory,$file)){
  if((Test-Path -LiteralPath $path) -and ((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Refusing redirected SSH paths'}
 }
 New-Item -ItemType Directory -Path $directory -Force | Out-Null
 $lines=@();if(Test-Path -LiteralPath $file){$lines=@(Get-Content -LiteralPath $file)}
 $parts=$p.public -split ' ';$pattern='(^|\s)'+[regex]::Escape($parts[0])+'\s+'+[regex]::Escape($parts[1])+'(\s|$)'
 if($p.kind -eq 'revoke'){$lines=@($lines | Where-Object {$_ -notmatch $pattern})}
 elseif(!@($lines | Where-Object {$_ -match $pattern}).Count){$lines+=@($p.public)}
 # Lock down the directory before creating or replacing the public-key file.
 foreach($path in @($directory,$file)){
  if($path -eq $file){[IO.File]::WriteAllText($file,($lines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))}
  $acl=Get-Acl -LiteralPath $path;$acl.SetAccessRuleProtection($true,$false)
  foreach($rule in @($acl.Access)){$acl.RemoveAccessRuleSpecific($rule)}
  foreach($identity in @($sid,'S-1-5-18','S-1-5-32-544')){
   $inherit=if($path -eq $directory){'ContainerInherit,ObjectInherit'}else{'None'}
   $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),'FullControl',$inherit,'None','Allow'))
  }
  Set-Acl -LiteralPath $path -AclObject $acl
  & icacls.exe $path /setowner ('*'+$sid) | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Unable to set SSH file ownership'}
 }
}
'Fleet task completed for '+$p.user
'''
