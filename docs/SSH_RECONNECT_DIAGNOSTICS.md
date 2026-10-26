# SSH reconnect diagnostics (offline)

`scripts/ssh-auth-reconnect-report.py` turns a bounded local OpenSSH/syslog sample into aggregate counts. It never connects to a host, starts a background task, invokes a shell, or changes server settings. Use it with logs you are authorized to inspect; do not paste raw journal lines into Huly.

## What the report says

It reports timestamped line counts for `Accepted publickey`, recognizable failed authentication, pre-auth markers, explicit `MaxStartups` and `PerSourcePenalties` log mentions, disconnects, timeouts, and explicit fail2ban ban/unban lines. It also counts explicit session-open/session-close records and estimates unmatched ongoing sessions by sshd PID. This last number is only useful when the capture contains complete, matching session lifecycle records. A long-lived reverse tunnel using `ssh -N` may have no shell/subsystem session-open record, so this report cannot prove that a transport is still connected.

The report groups recognized events into occupied UTC five-minute buckets and shows the observed timestamp window. Untimestamped or unclassified lines are reported as unknown and never guessed into a bucket. Traditional syslog timestamps need both `--year` and a known fixed `--timezone`; timestamps with missing or mixed offsets do not produce a reliable timeline. A sample with mixed ISO offsets keeps recognizable line totals but withholds its window and buckets.

Counts are log-line counts. Duplicate lines are retained and counted again. `Accepted publickey` establishes an authentication event, not an active tunnel or a rate-limit cause. An explicit MaxStartups or PerSourcePenalties log mention is evidence of that daemon message; absence from the captured sample is not proof that the condition did not occur. A firewall or hosting-provider throttle cannot be established without corresponding firewall/provider evidence. The tool does not infer a confirmed rate limit from event counts. The report's `attribution` is deliberately `none`: it cannot determine which Agent, service, or SSH principal generated a line.

Source grouping is optional (`--include-source-pseudonyms`). It emits only random per-run pseudonyms for sources with at least five recognized events, never an IP, port, username, key, or fingerprint. The salt is generated in memory for each invocation; pseudonyms are not joinable between reports. This is a source-address grouping, not a principal identity. Keep separate principals in separate input samples and separate reports. In particular, never combine the HOME backup MCP tunnel's restart evidence with ONEC Agent events; this tool cannot infer ownership from an sshd line. Huly should receive only the aggregate output, never the underlying log sample.

## Capture and run

Use an operator-approved host, principal scope, and time range. Unit names vary by distribution; `sshd`/`ssh` are common examples. This command is read-only and pipes the selected output directly into the local report process:

```sh
journalctl -u sshd -u ssh -o short-iso --since '30 minutes ago' --no-pager \
  | python3 scripts/ssh-auth-reconnect-report.py --stdin --format json
```

The tool reads at most 5 MiB and returns a generic error if that limit is exceeded. Narrow the authorized time range if needed. For an already collected local file, use `--input PATH --format json`. On systems using `/var/log/auth.log` or `/var/log/secure`, provide only an authorized, bounded local sample. For traditional syslog without year or zone in each timestamp, specify the host's known values explicitly:

```sh
python3 scripts/ssh-auth-reconnect-report.py --input PATH --format json \
  --year 2026 --timezone +03:00
```

Do not guess the year or timezone. If a sample mixes timestamp formats or offsets, resolve the source clock context and collect a coherent sample before drawing timeline conclusions. Keep the report output; discard or protect the raw sample according to the operator's data-handling rules.

The report accepts JSON (default operator recommendation) or a concise text summary:

```sh
journalctl -u sshd -u ssh -o short-iso --since '30 minutes ago' --no-pager \
  | python3 scripts/ssh-auth-reconnect-report.py --stdin --format text
```

## Read-only server context

Inspect the daemon's effective values separately; this does not alter them:

```sh
sshd -T | grep -E '^(maxstartups|persourcemaxstartups|persourcepenalties|persourcenetblocksize|maxsessions|logingracetime) '
```

On an installation where `sshd` is not on `PATH`, use the operator-approved absolute executable path. If fail2ban is installed, its status command is also read-only:

```sh
fail2ban-client status
```

The `sshd -T` output describes effective settings, not evidence that a limit triggered. Correlate explicit sshd events with fail2ban, firewall, provider, and client/Agent evidence where available. This script does not capture those sources automatically.

## Interpret the categories correctly

- `MaxStartups` concerns concurrent unauthenticated connections. A cumulative count of accepted authentications over 30 minutes does not establish that threshold was reached.
- `PerSourcePenalties` accumulate qualifying source penalties and may refuse later connections. A count is reported only when a log line explicitly names that feature; the parser does not infer a penalty from a generic denial.
- `MaxSessions` limits shell, login, and subsystem sessions per SSH network connection. It is not a cap on persistent forwarded TCP channels.
- OpenSSH `ControlMaster` reuses a connection among OpenSSH client processes that share the configured control socket. It does not configure embedded `russh` transport reuse.
- A repeated authentication may reflect a reconnect loop, but one log event is not necessarily one full successful session. Correlate timestamped server events with the exact Agent binary, its tunnel-start/exit logs, gateway, and service owner before assigning cause.
- Keep the HOME backup MCP tunnel as a separate principal from ONEC Agents. Do not merge its restarts or source identity into the ONEC event count.

These distinctions follow the [OpenSSH server configuration manual](https://man.archlinux.org/man/core/openssh/sshd_config.5.en) and [OpenBSD OpenSSH client configuration manual](https://man.openbsd.net/ssh_config.5).

## Huly 1C-1031 evidence contract

Attach only the JSON aggregate plus a short note stating the collection window, source log type, whether syslog year/timezone were explicit, and whether the output contained unknown/mixed-time warnings. Treat the report as offline parsing evidence only. It is not evidence that the reported incident had 162 events, that those events came from ONEC Agents, or that a server-side throttle occurred. Keep the HOME backup MCP tunnel separate. Do not post raw IPs, usernames, ports, key material, fingerprints, or journal lines. A production diagnosis still requires separately authorized source-exact Agent and gateway correlation; this utility does not perform it.
