# kagi

### SSH in. Forward out.

`kagi` is a small, focused SSH server for moving bytes safely: SOCKS5, local and remote port forwarding, and live byte streams, all behind SSH-key authentication and a declarative policy engine.

It is built on [russh](https://github.com/warp-tech/russh) and is intentionally not a general-purpose shell host. There is no shell, SFTP, X11, agent forwarding, or arbitrary command execution.

## Why kagi?

- **SSH-native access control.** Public keys map to users and groups; rules decide which hosts, CIDRs, ports, and directions are reachable.
- **SOCKS without a second daemon.** OpenSSH provides the local SOCKS listener; kagi handles the `direct-tcpip` channels and policy.
- **Remote forwarding with a global switch.** `-R` is opt-in, auditable, and constrained by per-user and global quotas.
- **Live byte streams.** Pipe a program through SSH, attach from the admin TUI, detach, reattach, and retrieve undelivered output within a retention window.
- **An admin surface that stays out of the way.** Sessions, forwards, streams, rules, logs, and a vt100 attach view in one TUI.
- **Rust, bounded, and boring in the good way.** Bounded queues, explicit limits, no shell execution, and a small attack surface.

## Quick start

```bash
# A test key for the examples
ssh-keygen -t ed25519 -f alice_key -N ''

# Start from the example configuration
cp kagi.example.toml kagi.toml
$EDITOR kagi.toml

# Validate without starting the server or generating a host key
cargo run -- check -c kagi.toml

# Run
cargo run -- serve -c kagi.toml
```

On first start, kagi generates an Ed25519 host key at `<config dir>/host_ed25519`, or at `server.host_key` when configured.

```toml
[server]
host_key = "/var/lib/kagi/host_ed25519"
```

The default listen address is `[::]:22`. Port 22 normally requires root or `CAP_NET_BIND_SERVICE`. On Linux this is normally dual-stack (IPv6 and IPv4). Bind it to a private interface or protect it with a firewall in production; if your system sets `net.ipv6.bindv6only=1`, use an explicit `0.0.0.0:22` or `[::]:22` listener as appropriate.

## Client recipes

```bash
# SOCKS5: OpenSSH terminates the local SOCKS listener
ssh -D 1080 -N alice@host

# Local forwarding
ssh -L 8080:internal:80 -N alice@host

# Remote forwarding; requires the global -R switch and a listen allow rule
ssh -R 9000:127.0.0.1:22 -N alice@host

# Random remote port; the listen rule must allow port = "*"
ssh -R 0:127.0.0.1:22 -N alice@host

# Normal user with a PTY: compact live forwarding status
ssh -t alice@host

# Normal user without a PTY: register stream
ssh -T alice@host
ssh -T alice@host register job   # or: ssh -T alice@host stream job
ssh -T alice@host list streams

# Anonymous user configured with skip_key_check = true
ssh -T anonymous@host
ssh -T -i any_key anonymous@host

# Admin TUI: an admin user, the `admin` command, and a PTY
ssh -t admin@host admin

# Admin queries
ssh admin@host list streams
ssh admin@host explain api.example.com:443

# Admin attach: TTY mode is a vt100 view with a fixed status bar
ssh -t admin@host attach alice/job
ssh -T admin@host attach alice/job
```

## Identity model

A login name resolves to exactly one `[users.*]` entry.

```toml
[users.alice]
keys = ["ssh-ed25519 AAAA..."]
groups = ["dev"]

[users."team-*"]
match = "glob"
keys = ["ssh-ed25519 AAAA..."]
groups = ["dev"]

[users.admin]
keys = ["ssh-ed25519 AAAA..."]
admin = true
```

- Usernames are case-sensitive.
- `match` is `exact` (default), `glob`, or `regex`.
- Exact entries win over patterns.
- Multiple matching patterns make the login ambiguous and are rejected.
- The session keeps the actual login name; the subject is the matched user entry.
- Keys, groups, rules, and admin status belong to the matched entry.

`anonymous` is not a special case in the auth engine. It is a normal user with `skip_key_check = true`:

```toml
[users.anonymous]
keys = []
skip_key_check = true
groups = ["guests"]
```

The anonymous stream owner is scoped to the session, e.g. `anonymous#12/s12`.

Admins are users with `admin = true`. Enter the TUI with:

```bash
ssh -t admin@host admin
```

Without a PTY, the `admin` command is rejected; use `-t` or `-tt`. Plain `ssh -T admin@host` returns a text overview.

## Policy

Rules live on users and groups. Groups are expanded into the user's effective rule set.

```toml
[server]
default_policy = "deny"   # deny = allowlist, allow = denylist

[groups.dev]

[[groups.dev.rules]]
action = "allow"
host = "*.example.com"
match = "glob"            # glob | regex | exact
port = "80,443"

[[groups.dev.rules]]
action = "allow"
cidr = "10.0.0.0/8"
port = "1-65535"

[[groups.dev.rules]]
action = "deny"
cidr = "169.254.169.254/32"
port = "*"
```

- `allow` and `deny` are both evaluated; the most restrictive result wins.
- A matching group deny is not overridden by a user allow.
- `host` rules match the requested hostname; `cidr` rules filter resolved addresses.
- Host and CIDR are mutually exclusive in one rule; a rule must contain one of them.
- Ports accept an integer, a comma-separated string, ranges, or `"*"`.
- `forward = "connect" | "listen" | "any"` defaults to `connect`.
- `-R` requires an allow rule with `forward = "listen"`.
- DNS is evaluated before connecting; only allowed candidate IPs are attempted.
- DNS answers are cached by their TTL. Established TCP streams keep their address; new channels resolve again when the cache expires.

For internal targets, combine a host allow with explicit private-range denies. A host allow alone trusts every address that hostname resolves to.

## Streams

A stream connects a client-side byte stream to the admin attach surface.

```bash
# Explicit name: alice/job
program | ssh -T alice@host register job   # or: ssh -T alice@host stream job

# Default name: alice/s<session_id>
ssh -T alice@host

# Link the other direction with a local bridge such as socat or a coproc
```

The client's stdin becomes channel input; the client's stdout receives data written by an attached admin. Registration requires `-T`; a PTY is rejected.

FIFO semantics:

- While nobody is attached, incoming bytes wait in a per-channel FIFO.
- The next attach drains the FIFO once, then switches to live delivery.
- Data that has already been delivered is not replayed on a later attach.
- A channel closed with pending data stays available until `stream_retained_timeout_secs`.
- A channel closed with an empty FIFO is removed immediately.
- FIFO capacity is configured per user, per channel:

```toml
[users.alice]
stream_buffer_bytes = 8388608   # 8 MiB default
```

## Admin TUI

```bash
ssh -t admin@host admin
```

Pages:

1. **Overview** — listener, uptime, sessions, streams, forwards, global `-R`, policy defaults
2. **Sessions** — login, subject, role, auth method, peer, state
3. **Streams** — owner/name, session, bytes, subscribers
4. **Forwards** — connect/listen targets, state, byte counters
5. **Rules** — effective user and group rules
6. **Logs** — recent audit events

Keys:

```text
1–6, Tab, Shift-Tab   switch page
j/k, arrows          move selection
Enter                attach selected stream
Ctrl+]               detach from attached stream
Ctrl+C               send SIGINT to attached target
x                    close selected session
r                    refresh
R                    reload configuration
?                    help
q                    quit
```

`ssh admin@host attach ...` with a PTY uses the same vt100 renderer and fixed top status line as the TUI. Without a PTY, attach is raw passthrough.

## Limits and rate limiting

All limits are configurable. These are the defaults:

| Limit | Default |
|---|---:|
| `max_sessions_per_user` | 16 |
| `max_sessions` | 1024 |
| `max_direct_channels_per_conn` | 256 |
| `max_direct_channels_global` | 4096 |
| `max_direct_channels_per_user` | 256 |
| `max_remote_forwards_per_conn` | 32 |
| `max_remote_forwards_per_user` | 32 |
| `max_remote_forwards_global` | 512 |
| `max_streams_per_user` | 16 |
| `stream_buffer_bytes` | 8 MiB per channel |
| `stream_broadcast_capacity` | 1024 |
| `stream_retained_timeout_secs` | 300 |
| `max_connections_per_ip` | 20 (IPv6 /64) |
| `connection_rate_per_min` | 60 |
| `auth_failures_per_min` | 10 |
| `auth_cooldown_secs` | 60 |
| `max_auth_attempts` | 3 |
| `inactivity_timeout_secs` | 3600 |
| `keepalive_interval_secs` | 30 |
| `keepalive_max` | 3 |
| `connect_timeout_secs` | 10 |
| `resolve_timeout_secs` | 5 |

Admins are exempt from user/global quotas. They are not exempt from pre-auth IP rate limits; successful authentication clears the per-IP auth-failure counter. SSH `none` probes and key-offer probes do not count as failures; only rejected `publickey` / `password` / keyboard-interactive attempts do. IPv6 peers are counted by `/64`.

`inactivity_timeout_secs` is an SSH connection-level inactivity timeout. Keepalive responses count as inbound activity. It is not a per-channel idle timeout.

## Scope

kagi is a forwarding and stream control plane, not a remote shell.

Supported:

- `direct-tcpip` for SOCKS5 and `-L`
- remote TCP listeners for `-R`
- TCP targets
- streams and admin attach
- admin TUI and one-shot commands

Not implemented:

- shell or arbitrary command execution
- SFTP
- X11
- agent forwarding
- remote Unix-domain socket listeners or Unix-domain targets

## Configuration reference

The complete annotated reference is [`kagi.example.toml`](kagi.example.toml). The short version:

- `[server]` — listen, host key, policy default, global `-R`, quotas, timeouts, rate limits
- `[animation]` — TTY status line
- `[log]` — level and text/json format
- `[groups.<name>]` — group rules
- `[users.<name>]` — key/pattern matching, keys, groups, admin, rules, stream FIFO size
- `[[groups.<name>.rules]]` / `[[users.<name>.rules]]` — host/CIDR/port/forward rules

## Build and test

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --lib --tests
cargo build --release
cargo audit

# Nix
nix build
```

`flake.nix` provides a development shell and package. `Cargo.lock` is committed.
