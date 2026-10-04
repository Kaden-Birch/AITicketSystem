"""Installer postflight: verify effective systemd and running-agent privileges."""
import subprocess
from pathlib import Path

EXPECTED = {'User': 'root', 'Group': 'root', 'NoNewPrivileges': 'no',
            'ProtectSystem': 'no', 'ProtectHome': 'no', 'PrivateTmp': 'no',
            'ProtectKernelTunables': 'no', 'ProtectKernelModules': 'no',
            'ProtectControlGroups': 'no', 'RestrictSUIDSGID': 'no',
            'PrivateUsers': 'no', 'DynamicUser': 'no'}
# Account creation, ownership and file access needed by fleet user/key jobs.
REQUIRED_CAPS = {'CHOWN': 0, 'DAC_OVERRIDE': 1, 'FOWNER': 3, 'SETGID': 6, 'SETUID': 7}


def errors(properties, status, cmdline, policy):
    failures = []
    for name, wanted in EXPECTED.items():
        if properties.get(name) != wanted:
            failures.append(f'{name}={properties.get(name, "missing")} (expected {wanted})')
    for name in ('RootDirectory', 'RootImage', 'ReadOnlyPaths', 'InaccessiblePaths'):
        if properties.get(name):
            failures.append(f'{name} restriction is still configured')
    # systemd can serialize an unset filter as "~": an empty deny list
    # blocks no calls. Actual allow/deny lists must still fail verification.
    if properties.get('SystemCallFilter', '').strip() not in ('', '~'):
        failures.append('SystemCallFilter restriction is still configured')
    if properties.get('ActiveState') != 'active':
        failures.append('Agent service is not active')
    if status.get('Uid', '').split() != ['0'] * 4 or status.get('Gid', '').split() != ['0'] * 4:
        failures.append('Running agent does not have root UID/GID')
    if status.get('NoNewPrivs') != '0':
        failures.append('Running agent still has NoNewPrivileges enabled')
    try:
        caps = int(status.get('CapEff', ''), 16)
    except ValueError:
        caps = 0
    missing = [name for name, bit in REQUIRED_CAPS.items() if not caps & (1 << bit)]
    if missing:
        failures.append('Running agent lacks capabilities: ' + ', '.join(missing))
    if not any(p in cmdline for p in ('/opt/aiticket-agent/agent.py','/opt/aiticket-agent/current/agent.py')) or 'run' not in cmdline:
        failures.append('Service is not running the installed agent command')
    if policy.get('enabled') is not True or policy.get('sudo') is not False:
        failures.append('Local direct shell execution policy is not enabled')
    return failures


def main():
    from commands import policy_config
    names = list(EXPECTED) + ['MainPID', 'ActiveState', 'RootDirectory', 'RootImage',
                             'ReadOnlyPaths', 'InaccessiblePaths', 'SystemCallFilter']
    result = subprocess.run(['systemctl', 'show', 'aiticket-agent', '--no-pager',
                             '--property=' + ','.join(names)],
                            check=True, capture_output=True, text=True)
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    try:
        pid = int(properties.get('MainPID', '0'))
        if pid <= 0:
            raise ValueError('No running agent PID')
        process = Path('/proc') / str(pid)
        status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines() if ':' in line)
        status = {key: value.strip() for key, value in status.items()}
        cmdline = (process / 'cmdline').read_bytes().decode().split('\0')
        policy = policy_config('/etc/aiticket-agent/policy.json')
        failures = errors(properties, status, cmdline, policy)
        # Detect a restart while the running-process checks were collected.
        current = subprocess.run(['systemctl', 'show', 'aiticket-agent', '--property=MainPID', '--value'],
                                 check=True, capture_output=True, text=True).stdout.strip()
        if current != str(pid):
            failures.append('Agent restarted during verification; rerun installation')
    except (OSError, ValueError) as exc:
        failures = [f'Cannot verify running agent permissions: {exc}']
    if failures:
        print('INSTALLATION PERMISSION CHECK FAILED:')
        for failure in failures:
            print(' - ' + failure)
        print('Inspect sudo systemctl cat aiticket-agent --no-pager for conflicting drop-ins. '
              'Correct the reported restrictions and rerun the installer. Enrollment is preserved.')
        raise SystemExit(1)
    print('Permission check passed: running root agent, required account/file capabilities, '
          'effective service restrictions disabled, valid enabled shell policy.')


if __name__ == '__main__':
    main()
