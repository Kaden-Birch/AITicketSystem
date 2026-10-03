# Proxmox discovery and source linking

Use **Proxmox** in the UI to add a cluster or standalone node. Supply a friendly name, primary IP address or HTTPS URL, full token ID and secret. Use **Add IP** for as many optional cluster-node endpoints as needed; bare IPv4/IPv6 addresses become HTTPS URLs on port 8006. Full URLs support custom ports and DNS names. Certificates verify by default; an optional absolute server-side CA file can be supplied. In Compose, mount that file read-only before entering its container path. Token secrets are encrypted and never redisplayed.

Connections use explicit application cluster namespaces. Create one for each actual cluster. The cluster card lists its primary and fallback endpoints. Use **Add IP → Save additional addresses** on that card to extend an existing cluster without re-entering credentials. Selecting an existing namespace in the creation form also reuses its saved token and CA settings. This confirmation is the authority for grouping endpoints, not their names or addresses. Incorrectly assigning unrelated clusters to the same namespace can conflate numeric guest IDs. Automatic detection of that misconfiguration is not implemented. The app does not claim a universal Proxmox cluster UUID exists in the resource response.

Test Connection separates API reachability, authentication outcome, inventory readability and effective permissions where available. A readable resource list may be filtered by privileges; it does not prove access to every guest/storage object. Permission gaps remain visible and are never repaired by broadening credentials. This milestone uses only GET `/version`, `/cluster/resources`, and `/access/permissions`. Installed compatibility remains unverified until explicitly configured against your environment.

Discovery is read-only and supports manual or scheduled refresh. It lists nodes, VMs, LXCs and node-specific storage objects without creating machines or enabling checks. Endpoints assigned to the same namespace update the same resource records. Unknown resource types are ignored. Templates remain excluded.

For each non-template resource, explicitly confirm a link to an existing machine or create a new machine. A Proxmox node and guest cannot share a machine identity. Linking an existing Linux-agent machine adds its Proxmox source without changing the agent credential or DHCP-based address observations. Choose expected state; intentional stopped guests default to stopped in the form. Storage checks monitor availability in this milestone, not capacity thresholds.

Linked checks, manual/scheduled discovery, and the cluster connection test try other endpoints in the namespace if an endpoint is unavailable. A failed endpoint alone does not mark the entire cluster unavailable while another endpoint returns the required resource data. Each node address still needs a valid, trusted TLS certificate. **Cluster credentials** replaces the token ID, secret and CA settings across all endpoints in that namespace. Successful discovery refreshes guest node location and updates the parent to the explicitly linked node machine. A move to an unlinked node clears a previous managed node dependency rather than suppressing against the wrong host. Linked UUID and history persist across migrations.

A missing resource is not automatically retired, since permissions and visibility can change. If you delete/recreate a guest or reuse its ID, explicitly retire the old identity before rediscovery. A fresh generation is then discovered without inheriting old machine links. Reuse without an observed/configured lifecycle boundary cannot be reliably detected from this API and remains a limitation.

Unlink disables the source check, invalidates its lease, and retains observations, incidents, machine and agent history. Retire also removes the old resource from active inventory. Relinking creates a new check while preserving old evidence. Detached incidents remain visible with the disabled source; unlinking does not assert recovery.

Inventory requests remain read-only. Operational commands continue to use their existing host permissions and approval rules; ambiguous write requests are not replayed through another endpoint.

## Scheduled refresh

Each cluster has an optional persistent 60–86400 second refresh interval, configured on its card; zero disables it. Saving the schedule keeps one active discovery schedule for the cluster and disables redundant endpoint schedules. The selected primary performs scheduled discovery with fallback to other saved endpoints. The worker leases one due refresh at a time and recovers expired leases after restart. Disabling or changing a schedule fences an in-flight scheduled response. Failed requests preserve inventory, report only the error class, and retry at the configured interval.

New resources are marked for review and never automatically create checks. Successful refreshes mark missing resources as not visible; permission changes or partial endpoint visibility can produce this warning. Only explicit administrator retirement disables a source and creates a new identity generation on reuse. Migration refreshes retain guest identities and update linked node dependencies. Manual refresh remains available.

## Upgrade

Rebuild the main application after pulling the update. No agent or Hermes update is
required. Existing endpoint IDs, resource links and histories remain intact;
connections in the same namespace appear together in one cluster card. Save the
cluster schedule to consolidate older per-endpoint schedules. For older endpoints
with different credentials, replace the cluster credential to synchronize them.

When linking an enrolled host from Host settings, choose **Online / running** or **Intentionally offline / stopped**. The application maps this to the selected resource: online/offline for nodes and running/stopped for VMs and containers. Enrollment and agent credentials are preserved.
