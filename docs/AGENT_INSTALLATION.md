# Agent installation and updates

The Agent installs under one current-user-owned root:

| OS | Root |
| --- | --- |
| Linux | `$XDG_DATA_HOME/hostlink/Agent`, otherwise `$HOME/.local/share/hostlink/Agent` |
| Windows | `%LOCALAPPDATA%\HostLink\Agent` |

`hostlink-agent install` accepts a bootstrap-verified executable, enrolls the machine in the Hub, and publishes the executable to `ROOT/bin`. Temporary download files are not installed. Keys, configuration and Apalis jobs live outside `bin`.

The private `ROOT/state/manifest.json` records enrollment-key identity. Do not delete or replace it as part of an executable update.

## Service lifecycle

`install` does not itself register a persistent OS user service. Use `hostlink-agent service install` and `service start` for persistent operation; see [Agent lifecycle](AGENT_LIFECYCLE.md).

## Local repair through the same invite

`hostlink invite NAME --os windows|linux` selects fresh enrollment when the canonical name is absent from the authenticated Hub inventory, or identity-preserving repair when it identifies one existing machine. Execute the single resulting command at the target in a local or RDP user session. All downloads, HTTPS enrollment and pinned gateway authentication originate from that target; an existing remote Agent connection is not required.

The bootstrap retains its fixed GitHub release URL, exact RAW SHA-256 check and platform selection. It passes the existing machine ID to the verified installer. A repair invitation cannot initialize a missing root, and a fresh invitation cannot adopt an existing root. `--token-only` retains its manual fresh-invite semantics.

The installer verifies the stable private root, manifest-bound state, exact machine name/ID, both private SSH identities, assigned port, gateway pin files, jobs directory/database, and OS service ownership. The Controller-selected SSH protocol login can differ from the existing login; after Hub authentication it is published in the candidate configuration and manifest in the same repair transaction. It does not change the OS account or service owner. The installer preserves the SSH listener/Board addresses and Controller authorization file. A stopped or missing owned service is registered/started by the same bootstrap. An already matching service registration is reused. Foreign tasks/units, unsafe links/ACLs, corrupt manifests, changed identity, and uncertain earlier attempts fail before publication.

On Windows, repair preflight also accepts SQLite database and WAL/SHM files with the single current-user-only full-access ACE inherited from the verified private jobs directory. It checks each existing file through a handle without changing its ACL or contents; other files still require the protected private ACL. SQLite can recreate sidecars during normal operation, so each repair checks whichever sidecars exist at that time.

The installer obtains current approved routes and Ed25519 pins from the authenticated Hub, verifies unchanged identity/port, and authenticates the existing reverse key to at least one approved gateway before replacing files. It holds `update.lock`, removes only an owned service when publication is necessary, and acquires the canonical `jobs/runner.lock` before publication. Windows publication additionally requires an independently running staged image and removal of the owned Scheduler task. Jobs remain outside the transaction; repair does not migrate or initialize Apalis.

### Lost SSH keys

After inspecting the exact inventory identity, an operator can explicitly authorize replacement within the same command:

```sh
hostlink invite lab-host --os windows --replace-identity FULL_MACHINE_ID
```

The full ID must match that canonical name in the authenticated inventory. The target requires an interactive terminal and typing the same full ID before generating replacement keys. The Hub issues a distinct rotation invitation. Machine ID, assigned port and jobs remain; both SSH keys change, including the Controller's Agent host pin. Replacement tolerates missing or corrupt **private SSH key files only**. The manifest, machine record, config and all other state must still validate. An unidentified or more broadly damaged root requires authenticated reconciliation; the installer does not delete or silently adopt it.

### Interrupted repair and rollback

Before sending a one-use request, the installer durably writes `repair.pending` and `.repair-UUID/attempt/` with the attempted keys and public identity; it never saves the invite token there. A failed/unacknowledged HTTPS response, invalid reply, or failed approved-gateway probe leaves these files for reconciliation and retains the original installation. Do not resend that token or remove the marker merely to retry. Installed runtime, updater and service start/install refuse a pending transaction.

Publication uses same-filesystem directory renames under the shared locks. The private `.repair-UUID` directory retains `original-state` and, when present, `original-bin`; successful repair does not erase these backups. An unchanged repair removes only its newly generated candidate copies. A filesystem publication failure attempts local rollback and reports any incomplete rollback. For an identity-preserving repair, successful rollback clears the marker and attempts to restore the previous service registration/activity. A committed key rotation cannot roll back Hub authorization locally: it retains the marker and attempted new keys even after restoring original files. Power loss between directory renames also requires reconciliation before service startup. OS service restoration/start failure is reported separately from file publication.

Use a reviewed release containing this implementation on Controller, Hub and Agent before a native canary. Linux fixture/SSH tests and Windows cross-checks do not establish Task Scheduler, real Win7/PowerShell2, Win10/11 or native end-to-end acceptance.

## Updates

```text
hostlink-agent update
hostlink-agent update --version 0.1.0
```

The current updater selects the exact raw executable from GitHub Releases from the public repository without a GitHub credential and verifies its published SHA-256 and binary identity.

The Agent must be stopped before update. Publication holds `update.lock` and `jobs/runner.lock`; on Windows the user Task Scheduler task must also be removed, and an independently verified executable outside the installed `bin` performs the update. The updater does not automatically restart the Agent or restore a task.

Interrupted power loss may require manual repair. See [Windows offline update](AGENT_UPDATE_WINDOWS.md) and [GitHub Releases](GITHUB_RELEASES.md).
