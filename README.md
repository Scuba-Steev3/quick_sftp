# quick_sftp.py

`quick_sftp.py` is a lightweight, hardened SFTP-only server for Kali/Linux and other Python-supported systems.

It is designed for quick file transfer workflows, labs, internal tooling, temporary drop zones, and controlled security testing environments where you want a small Python-based SFTP service without enabling a shell, SCP, PTY, X11 forwarding, or agent forwarding.

> **Security note**
>
> `quick_sftp.py` uses AsyncSSH's SFTP server with a virtual chroot and additional path checks. This is useful for containment, but it should not be treated as a complete operating-system sandbox for hostile or untrusted users. For high-risk deployments, run it as a dedicated Unix user and pair it with OS-level isolation such as a container, real chroot, AppArmor, SELinux, systemd sandboxing, filesystem permissions, and firewall allowlists.

---

## Table of contents

- [Features](#features)
- [Security posture](#security-posture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Authentication modes](#authentication-modes)
  - [Public-key authentication](#public-key-authentication)
  - [Username and password authentication](#username-and-password-authentication)
  - [Public-key plus password fallback](#public-key-plus-password-fallback)
- [Remote and LAN access](#remote-and-lan-access)
- [Client examples](#client-examples)
- [Command-line options](#command-line-options)
- [Recommended production setup](#recommended-production-setup)
- [systemd service example](#systemd-service-example)
- [Logging](#logging)
- [File and directory permissions](#file-and-directory-permissions)
- [Operational examples](#operational-examples)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

---

## Features

- SFTP-only service powered by AsyncSSH.
- Public-key authentication support via an OpenSSH-style `authorized_keys` file.
- Username/password authentication support when explicitly enabled.
- Password loading from:
  - interactive prompt,
  - environment variable,
  - protected password file.
- Localhost-only binding by default.
- Explicit confirmation required before listening on non-loopback addresses.
- Explicit extra confirmation required before allowing password auth on non-loopback addresses.
- In-memory password authentication throttling and temporary lockout.
- Virtual chroot using the selected SFTP root directory.
- Optional strict realpath guard to reduce symlink escape risk.
- Client-created symlinks and hardlinks disabled by default.
- Optional read-only mode.
- Optional per-file upload size limit.
- Host key, password file, authorized keys, and root directory permission checks.
- Structured logging to stderr or a log file.
- Graceful shutdown on `SIGINT` and `SIGTERM`.
- Explicitly disables common SSH features not needed for SFTP:
  - shell,
  - exec,
  - SCP,
  - PTY,
  - line editor,
  - X11 forwarding,
  - SSH agent forwarding,
  - GSSAPI auth/key exchange,
  - compression by default.

---

## Security posture

`quick_sftp.py` is intentionally conservative by default.

| Area | Default behavior |
| --- | --- |
| Bind address | `127.0.0.1` |
| Remote listen | Denied unless `--allow-remote-listen` is set |
| Password auth | Disabled unless `--enable-password-auth` is set |
| Remote password auth | Denied unless `--allow-remote-password-auth` is also set |
| Public-key auth | Supported with `--authorized-keys` |
| Shell/exec access | Not provided |
| SCP | Disabled |
| PTY | Disabled |
| X11 forwarding | Disabled |
| Agent forwarding | Disabled |
| Compression | Disabled unless `--enable-compression` is set |
| Symlink creation | Disabled unless `--allow-symlinks` is set |
| Hardlink creation | Disabled unless `--allow-hardlinks` is set |
| Path guard | Enabled unless `--no-strict-path-check` is set |
| Root permissions | Refuses unsafe group/world-writable roots |
| Secret file permissions | Refuses unsafe group/world-readable files on POSIX systems |

This app is appropriate for controlled environments. It is not intended to replace a fully managed production OpenSSH SFTP subsystem for high-volume, multi-tenant, or hostile-user environments.

---

## Requirements

- Python 3.10 or newer is recommended.
- `asyncssh`
- OpenSSH client tools for generating host/client keys and connecting with `sftp`.

Install dependency:

```bash
python3 -m pip install asyncssh
```

On Kali/Debian/Ubuntu, make sure Python and OpenSSH tooling are available:

```bash
sudo apt update
sudo apt install -y python3 python3-pip openssh-client
python3 -m pip install asyncssh
```

---

## Installation

Clone or copy the script into your project:

```bash
chmod +x quick_sftp.py
```

Create a host key:

```bash
ssh-keygen -t ed25519 -f ./ssh_host_ed25519_key -N ""
chmod 600 ./ssh_host_ed25519_key
```

Create the SFTP root:

```bash
mkdir -p ./sftp-root
chmod 700 ./sftp-root
```

Run help:

```bash
./quick_sftp.py --help
```

---

## Quick start

### Local password-based SFTP server

```bash
./quick_sftp.py --enable-password-auth --user alice
```

The server will prompt for the password interactively.

Connect from the same machine:

```bash
sftp -P 2222 alice@127.0.0.1
```

### Local public-key-only SFTP server

Create an authorized keys file:

```bash
mkdir -p ./.ssh
cp ~/.ssh/id_ed25519.pub ./.ssh/sftp_authorized_keys
chmod 600 ./.ssh/sftp_authorized_keys
```

Start the server:

```bash
./quick_sftp.py --authorized-keys ./.ssh/sftp_authorized_keys
```

Connect:

```bash
sftp -P 2222 -i ~/.ssh/id_ed25519 sftpuser@127.0.0.1
```

---

## Authentication modes

`quick_sftp.py` requires at least one authentication method:

- `--authorized-keys`
- `--enable-password-auth`

If neither is provided, the server exits.

### Public-key authentication

Public-key authentication is the recommended mode.

```bash
./quick_sftp.py \
  --user sftpuser \
  --authorized-keys ./.ssh/sftp_authorized_keys
```

Create an authorized keys file:

```bash
mkdir -p ./.ssh
cp ~/.ssh/id_ed25519.pub ./.ssh/sftp_authorized_keys
chmod 600 ./.ssh/sftp_authorized_keys
```

Connect:

```bash
sftp -P 2222 -i ~/.ssh/id_ed25519 sftpuser@127.0.0.1
```

A more restrictive `authorized_keys` entry can be useful when this service is exposed beyond localhost. Example:

```text
no-agent-forwarding,no-X11-forwarding,no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@example
```

### Username and password authentication

Password authentication is still supported, but it must be enabled explicitly.

#### Interactive prompt

```bash
./quick_sftp.py --enable-password-auth --user alice
```

#### Environment variable

```bash
export SFTP_PASSWORD='use-a-long-random-password-here'

./quick_sftp.py \
  --enable-password-auth \
  --user alice
```

By default, the script reads from `SFTP_PASSWORD`.

Use a custom environment variable name:

```bash
export QUICK_SFTP_PASSWORD='use-a-long-random-password-here'

./quick_sftp.py \
  --enable-password-auth \
  --password-env QUICK_SFTP_PASSWORD \
  --user alice
```

#### Password file

```bash
install -m 600 /dev/null ./sftp.password
printf '%s\n' 'use-a-long-random-password-here' > ./sftp.password

./quick_sftp.py \
  --enable-password-auth \
  --user alice \
  --password-file ./sftp.password
```

The password file must be protected. On POSIX systems, the script rejects group/world-readable secret files.

#### Password length

The default minimum password length is 16 characters.

Change it:

```bash
./quick_sftp.py \
  --enable-password-auth \
  --user alice \
  --min-password-length 24
```

#### Password lockout

The script includes simple in-memory throttling:

```bash
./quick_sftp.py \
  --enable-password-auth \
  --user alice \
  --max-auth-failures 5 \
  --lockout-seconds 300
```

This lockout resets when the process restarts. Use firewall rules, fail2ban, reverse proxy controls, or infrastructure-level protections for stronger persistent enforcement.

### Public-key plus password fallback

You can enable both methods:

```bash
./quick_sftp.py \
  --user alice \
  --authorized-keys ./.ssh/sftp_authorized_keys \
  --enable-password-auth
```

In this configuration, clients can authenticate with either a valid public key or the configured password.

---

## Remote and LAN access

By default, the server listens only on localhost:

```bash
--host 127.0.0.1
```

To listen on all interfaces:

```bash
./quick_sftp.py \
  --host 0.0.0.0 \
  --allow-remote-listen \
  --authorized-keys ./.ssh/sftp_authorized_keys
```

To listen on a specific LAN interface:

```bash
./quick_sftp.py \
  --host 192.168.1.50 \
  --allow-remote-listen \
  --authorized-keys ./.ssh/sftp_authorized_keys
```

Remote password authentication requires an additional explicit flag:

```bash
./quick_sftp.py \
  --host 0.0.0.0 \
  --allow-remote-listen \
  --enable-password-auth \
  --allow-remote-password-auth \
  --user alice \
  --password-file ./sftp.password
```

Remote password authentication is not recommended for Internet exposure. Use public-key authentication, firewall allowlists, VPN access, and monitoring whenever possible.

---

## Client examples

### Connect with password

```bash
sftp -P 2222 alice@127.0.0.1
```

### Connect with a key

```bash
sftp -P 2222 -i ~/.ssh/id_ed25519 sftpuser@127.0.0.1
```

### Upload a file

```bash
sftp -P 2222 alice@127.0.0.1
sftp> put ./local-file.txt
sftp> ls
sftp> bye
```

### Download a file

```bash
sftp -P 2222 alice@127.0.0.1
sftp> get remote-file.txt
sftp> bye
```

### Batch upload

Create `batch.sftp`:

```text
put report.txt
put evidence.zip
ls
bye
```

Run:

```bash
sftp -P 2222 -b batch.sftp alice@127.0.0.1
```

---

## Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `-p`, `--port` | `2222` | TCP port to listen on. |
| `--host` | `127.0.0.1` | Listen address. Non-loopback addresses require `--allow-remote-listen`. |
| `--allow-remote-listen` | disabled | Allow binding to non-loopback addresses such as `0.0.0.0`. |
| `-r`, `--root` | `./sftp-root` | Directory exposed as the SFTP root. |
| `-u`, `--user` | `sftpuser` | SFTP username. |
| `--host-key` | `./ssh_host_ed25519_key` | SSH host private key path. |
| `--authorized-keys` | unset | OpenSSH authorized keys file. Recommended. |
| `--enable-password-auth` | disabled | Enable username/password auth. |
| `--allow-remote-password-auth` | disabled | Allow password auth on non-loopback listens. Requires `--allow-remote-listen` and `--enable-password-auth`. |
| `--password-env` | `SFTP_PASSWORD` | Environment variable used for password auth. |
| `--password-file` | unset | Protected file containing the password on the first line. |
| `--min-password-length` | `16` | Minimum accepted password length. |
| `--max-auth-failures` | `5` | Failed password attempts before lockout. |
| `--lockout-seconds` | `300` | Temporary lockout duration in seconds. |
| `--read-only` | disabled | Deny write operations. |
| `--allow-symlinks` | disabled | Allow clients to create symlinks. |
| `--allow-hardlinks` | disabled | Allow clients to create hardlinks. |
| `--no-strict-path-check` | disabled | Disable the realpath guard that reduces symlink escape risk. |
| `--max-upload-bytes` | `0` | Per-file upload limit. `0` means unlimited. |
| `--login-timeout` | `30` | SSH login timeout in seconds. |
| `--keepalive-interval` | `30` | SSH keepalive interval in seconds. |
| `--keepalive-count-max` | `3` | Maximum unanswered keepalives before disconnect. |
| `--enable-compression` | disabled | Enable SSH compression. Disabled by default. |
| `--log-level` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `--log-file` | unset | Optional log file path. Defaults to stderr. |

---

## Recommended production setup

For a more official or production-like deployment:

1. Create a dedicated service account:

   ```bash
   sudo useradd --system --create-home --shell /usr/sbin/nologin quick-sftp
   ```

2. Install the app in a controlled location:

   ```bash
   sudo install -m 0755 quick_sftp.py /opt/quick-sftp/quick_sftp.py
   ```

3. Create a dedicated root directory:

   ```bash
   sudo mkdir -p /srv/quick-sftp/root
   sudo chown quick-sftp:quick-sftp /srv/quick-sftp/root
   sudo chmod 700 /srv/quick-sftp/root
   ```

4. Create a host key:

   ```bash
   sudo ssh-keygen -t ed25519 -f /etc/quick-sftp/ssh_host_ed25519_key -N ""
   sudo chown root:root /etc/quick-sftp/ssh_host_ed25519_key
   sudo chmod 600 /etc/quick-sftp/ssh_host_ed25519_key
   ```

5. Use public-key authentication where possible:

   ```bash
   sudo install -m 600 -o quick-sftp -g quick-sftp /dev/null /etc/quick-sftp/authorized_keys
   sudoedit /etc/quick-sftp/authorized_keys
   ```

6. Restrict network exposure:

   ```bash
   sudo ufw allow from 192.168.1.0/24 to any port 2222 proto tcp
   ```

7. Run under systemd with hardening options.

---

## systemd service example

Create `/etc/systemd/system/quick-sftp.service`:

```ini
[Unit]
Description=quick_sftp.py hardened SFTP service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=quick-sftp
Group=quick-sftp
WorkingDirectory=/opt/quick-sftp
ExecStart=/usr/bin/python3 /opt/quick-sftp/quick_sftp.py \
  --host 127.0.0.1 \
  --port 2222 \
  --user sftpuser \
  --root /srv/quick-sftp/root \
  --host-key /etc/quick-sftp/ssh_host_ed25519_key \
  --authorized-keys /etc/quick-sftp/authorized_keys \
  --log-level INFO

Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/quick-sftp/root
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quick-sftp.service
sudo systemctl status quick-sftp.service
```

View logs:

```bash
journalctl -u quick-sftp.service -f
```

### systemd with password file

Create a password file:

```bash
sudo install -m 600 -o quick-sftp -g quick-sftp /dev/null /etc/quick-sftp/sftp.password
sudo sh -c "printf '%s\n' 'use-a-long-random-password-here' > /etc/quick-sftp/sftp.password"
```

Use this `ExecStart`:

```ini
ExecStart=/usr/bin/python3 /opt/quick-sftp/quick_sftp.py \
  --host 127.0.0.1 \
  --port 2222 \
  --user alice \
  --root /srv/quick-sftp/root \
  --host-key /etc/quick-sftp/ssh_host_ed25519_key \
  --enable-password-auth \
  --password-file /etc/quick-sftp/sftp.password \
  --log-level INFO
```

---

## Logging

By default, logs are written to stderr:

```bash
./quick_sftp.py --authorized-keys ./.ssh/sftp_authorized_keys
```

Write logs to a file:

```bash
./quick_sftp.py \
  --authorized-keys ./.ssh/sftp_authorized_keys \
  --log-file ./quick-sftp.log
```

Increase verbosity:

```bash
./quick_sftp.py \
  --authorized-keys ./.ssh/sftp_authorized_keys \
  --log-level DEBUG
```

Do not leave debug logging enabled in sensitive environments unless you have reviewed what is being logged and where the logs are stored.

---

## File and directory permissions

The app performs permission checks to avoid common unsafe deployments.

### Host key

Recommended:

```bash
chmod 600 ./ssh_host_ed25519_key
```

### Authorized keys

Recommended:

```bash
chmod 600 ./.ssh/sftp_authorized_keys
```

### Password file

Recommended:

```bash
chmod 600 ./sftp.password
```

### SFTP root

Recommended:

```bash
chmod 700 ./sftp-root
```

The SFTP root should not be group/world-writable.

---

## Operational examples

### Read-only SFTP share

```bash
./quick_sftp.py \
  --authorized-keys ./.ssh/sftp_authorized_keys \
  --root ./shared-files \
  --read-only
```

### Upload drop zone with max file size

Limit each uploaded file to 100 MiB:

```bash
./quick_sftp.py \
  --enable-password-auth \
  --user uploader \
  --root ./uploads \
  --max-upload-bytes 104857600
```

### LAN-only public-key SFTP

```bash
./quick_sftp.py \
  --host 192.168.1.50 \
  --allow-remote-listen \
  --authorized-keys ./.ssh/sftp_authorized_keys \
  --root ./sftp-root
```

### Password auth on localhost only

```bash
./quick_sftp.py \
  --host 127.0.0.1 \
  --enable-password-auth \
  --user alice
```

### Password auth on LAN with explicit acknowledgement

```bash
./quick_sftp.py \
  --host 0.0.0.0 \
  --allow-remote-listen \
  --enable-password-auth \
  --allow-remote-password-auth \
  --user alice \
  --password-file ./sftp.password
```

---

## Troubleshooting

### `Missing host key`

Create one:

```bash
ssh-keygen -t ed25519 -f ./ssh_host_ed25519_key -N ""
chmod 600 ./ssh_host_ed25519_key
```

### `No authentication method configured`

Provide either public-key auth:

```bash
./quick_sftp.py --authorized-keys ./.ssh/sftp_authorized_keys
```

Or explicitly enable password auth:

```bash
./quick_sftp.py --enable-password-auth --user alice
```

### `Refusing to bind to non-loopback address`

You are trying to listen on a remote/LAN address without acknowledgement.

Use:

```bash
--allow-remote-listen
```

Example:

```bash
./quick_sftp.py \
  --host 0.0.0.0 \
  --allow-remote-listen \
  --authorized-keys ./.ssh/sftp_authorized_keys
```

### `Refusing remote password-auth service`

Remote password auth requires explicit acknowledgement.

Use public-key auth instead, or add:

```bash
--allow-remote-password-auth
```

Only use this after reviewing the risk.

### `Password is too short`

Use a longer password or change the policy:

```bash
./quick_sftp.py \
  --enable-password-auth \
  --min-password-length 24
```

### `Permission denied` during upload

Check:

- Is `--read-only` enabled?
- Is the SFTP root writable by the user running `quick_sftp.py`?
- Is `--max-upload-bytes` smaller than the file?
- Are filesystem permissions preventing writes?

### `Path escapes SFTP root`

The strict path guard blocked a path that resolved outside the configured root. This is usually caused by symlinks or unusual path layouts.

Recommended fix: remove symlinks that point outside the SFTP root.

You can disable the guard with:

```bash
--no-strict-path-check
```

Disabling the guard is not recommended for untrusted clients.

### Client warns about host key changed

The server host key changed. Confirm this was intentional.

Remove the old known-hosts entry only if you trust the new host key:

```bash
ssh-keygen -R "[127.0.0.1]:2222"
```

Reconnect:

```bash
sftp -P 2222 alice@127.0.0.1
```

---

## Limitations

- The virtual chroot is not a complete OS sandbox.
- The password lockout is in-memory and resets on restart.
- This app is single-process and intentionally lightweight.
- It is not a replacement for a fully managed OpenSSH SFTP deployment in high-risk, high-volume, or multi-tenant environments.
- There is no built-in TLS because SFTP runs over SSH.
- There is no database-backed user system.
- There is no built-in multi-user home directory mapping.
- There is no built-in quota system beyond the optional per-file upload size limit.

---

## Development

### Suggested project layout

```text
quick-sftp/
├── quick_sftp.py
├── README.md
├── LICENSE
├── pyproject.toml
└── tests/
```

### Basic syntax check

```bash
python3 -m py_compile quick_sftp.py
```

### Suggested linting

```bash
python3 -m pip install ruff mypy
ruff check quick_sftp.py
mypy quick_sftp.py
```

### Suggested test areas

- Argument validation.
- Host key permission validation.
- Authorized keys permission validation.
- Password file validation.
- Localhost vs remote-listen gating.
- Password-auth lockout behavior.
- Read-only SFTP behavior.
- Upload size limit behavior.
- Symlink and hardlink policy behavior.
- Strict path guard behavior.

---

## Security checklist

Before exposing this service beyond localhost:

- [ ] Use public-key authentication.
- [ ] Avoid password auth on public networks.
- [ ] Bind to a specific interface instead of `0.0.0.0` where possible.
- [ ] Use firewall allowlists.
- [ ] Run as a dedicated unprivileged user.
- [ ] Use OS-level isolation for untrusted clients.
- [ ] Protect host keys and secret files with `chmod 600`.
- [ ] Keep the SFTP root non-world-writable.
- [ ] Enable external monitoring/log forwarding.
- [ ] Rotate passwords and keys when access changes.
- [ ] Review logs regularly.
- [ ] Keep Python and dependencies updated.

---

## Disclaimer

Use this tool only on systems and networks where you are authorized to operate it. You are responsible for complying with applicable laws, policies, and organizational security requirements.
