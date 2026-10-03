# Fleet management

Update and rebuild the main application, then open **Fleet**. Existing shell-capable agents need no update. Fleet executes ordinary durable agent commands; it does not use SSH or make AI calls per host.

## SSH access

Generate an Ed25519 key pair with a descriptive name and optional private-key passphrase. Download the private key to your connecting computer, confirm you saved it, and remove its stored server copy. Before confirmation it remains downloadable; after confirmation only the public key remains in the current database. Old database backups may retain the encrypted private key. Downloads require the administrator session and CSRF-protected POST and are not cached. Use your reverse proxy's HTTPS URL when downloading keys over an untrusted network.

On the connecting computer, restrict the downloaded private key and use it:

```bash
chmod 600 /path/to/downloaded-key
ssh -i /path/to/downloaded-key username@VM_IP
```

Choose **Deploy SSH public key**, the existing Linux username, the key, and target hosts. Review and launch. Other authorized keys are preserved and repeated deployment does not duplicate the key. **Remove SSH public key** removes that key from the selected accounts, including authorized-key lines with restrictions. Each VM retains its own SSH host keys.

## Users and software

**Create user** creates a new account with a home directory and Bash shell, optionally adding an SSH key. Standard access adds no administrator group; Administrator adds the existing `sudo` group. Additional group names must already exist on each host. Existing users are preserved and return a failed command explaining why; this release does not modify existing account permissions. No password or passwordless sudo rule is installed; sudo use depends on the host's existing configuration.

**Install packages** accepts Ubuntu/Debian package names and runs apt update/install. **Custom shell script** accepts your exact script. User creation and package installation require appropriate OS privileges on the agent. Full access in the application does not change the agent's Linux identity or systemd restrictions.

## Targets, permissions and results

Select individual hosts, an existing host group, or all listed hosts. Network appliances are excluded. Review the selected machines, host policies and exact command before launching. Start with one host before deploying broadly. Jobs can contain up to 200 hosts, and show individual command states/output. Job pages update automatically. Approval-required commands are approved in the existing host workspace; Full access queues them immediately. Read-only policy blocks changes. Command UUIDs, expiry, revocation, cancellation and unknown-outcome reconciliation follow the existing command ledger.

Offline, disabled or busy agents are reported as blocked without dispatch. There is no indefinite offline queue. Fix the blocker, then use **Reuse task with new targets** and select only the hosts needing another attempt. Reusing a task requires a new review and creates a new job. Refreshing/resubmitting the same reviewed submission does not launch duplicate commands. If a server stops during submission, queued rows may remain without an execution record; inspect the host ledger before launching another task. Never automatically replay an unknown outcome.

Fleet job definitions/scripts are encrypted in application storage; private keys and passphrases are excluded from audit logs. Fleet records are retained in full database backups, not the inventory configuration export. This milestone does not implement continuous configuration enforcement, scheduled jobs, automatic rollback, or AI fleet tools.

Before submission, hosts need a fresh shell-capable agent and an application access mode permitting the task. The current agent installer runs as root and verifies its effective privileges. Reinstall legacy agents with the [one-command installer](agent.md); a GUI Full access setting alone does not elevate an older unprivileged process. Retry failed/blocked targets individually after correcting the cause.

## Workspace layout

Configure a task and select hosts in the main workspace; SSH keys and recent jobs are in the sidebar. The selected-host count updates as you choose a group or individual hosts. Only fields for the selected task are shown. Review still precedes launch, and host permissions remain unchanged.

Job pages show readable outcomes and guidance, with request references and output under **Execution details**. Submitted commands remain available for inspection. Unknown outcomes are labelled **Needs verification**, including results with a recorded zero exit code. The review screen does not poll a POST-only endpoint; job results continue updating automatically.
