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

## Updates

```text
hostlink-agent update
hostlink-agent update --version 0.1.0
```

The current updater selects the exact raw executable from GitHub Releases from the public repository without a GitHub credential and verifies its published SHA-256 and binary identity.

The Agent must be stopped before update. Publication holds `update.lock` and `jobs/runner.lock`; on Windows the user Task Scheduler task must also be removed, and an independently verified executable outside the installed `bin` performs the update. The updater does not automatically restart the Agent or restore a task.

Interrupted power loss may require manual repair. See [Windows offline update](AGENT_UPDATE_WINDOWS.md) and [GitHub Releases](GITHUB_RELEASES.md).
