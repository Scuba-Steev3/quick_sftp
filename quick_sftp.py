#!/usr/bin/env python3
"""
Hardened lightweight SFTP server using AsyncSSH.

Security posture:
- Key authentication by default.
- Password authentication only when explicitly enabled.
- Localhost bind by default; remote bind requires --allow-remote-listen.
- OS-level file permission checks for root, host key, and authorized_keys.
- Virtual chroot via AsyncSSH plus a strict realpath guard to reduce symlink escapes.
- Basic in-memory password throttling/lockout.
- No shell, exec, PTY, agent forwarding, X11 forwarding, or SCP.
- SFTP-only service.

Install:
    python3 -m pip install asyncssh

Create a host key:
    ssh-keygen -t ed25519 -f ./ssh_host_ed25519_key -N ""

Create an authorized_keys file:
    mkdir -p ./.ssh
    cp ~/.ssh/id_ed25519.pub ./.ssh/sftp_authorized_keys
    chmod 600 ./.ssh/sftp_authorized_keys

Run key-only:
    ./hardened_sftp.py --authorized-keys ./.ssh/sftp_authorized_keys

Connect:
    sftp -P 2222 -i ~/.ssh/id_ed25519 sftpuser@127.0.0.1
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hmac
import ipaddress
import logging
import os
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import asyncssh

try:
    from asyncssh import SFTPPermissionDenied, SFTPOpUnsupported
except ImportError:  # pragma: no cover - compatibility fallback
    from asyncssh.sftp import SFTPPermissionDenied, SFTPOpUnsupported  # type: ignore

try:
    from asyncssh.constants import (
        ACE4_APPEND_DATA,
        ACE4_WRITE_ATTRIBUTES,
        ACE4_WRITE_DATA,
        FXF_ACCESS_DISPOSITION,
        FXF_APPEND,
        FXF_APPEND_DATA,
        FXF_CREAT,
        FXF_CREATE_NEW,
        FXF_CREATE_TRUNCATE,
        FXF_EXCL,
        FXF_OPEN_OR_CREATE,
        FXF_TRUNC,
        FXF_TRUNCATE_EXISTING,
        FXF_WRITE,
    )
except ImportError:  # pragma: no cover - compatibility fallback
    # SFTPv3 values are stable. SFTPv5/6 values below are used only as a
    # conservative fallback if AsyncSSH ever stops exporting constants.
    ACE4_WRITE_DATA = 0x00000002
    ACE4_APPEND_DATA = 0x00000004
    ACE4_WRITE_ATTRIBUTES = 0x00000100
    FXF_WRITE = 0x00000002
    FXF_APPEND = 0x00000004
    FXF_CREAT = 0x00000008
    FXF_TRUNC = 0x00000010
    FXF_EXCL = 0x00000020
    FXF_ACCESS_DISPOSITION = 0x00000007
    FXF_CREATE_NEW = 0x00000000
    FXF_CREATE_TRUNCATE = 0x00000001
    FXF_OPEN_OR_CREATE = 0x00000003
    FXF_TRUNCATE_EXISTING = 0x00000004
    FXF_APPEND_DATA = 0x00000008


LOG = logging.getLogger("hardened_sftp")

WRITE_PFLAGS = FXF_WRITE | FXF_APPEND | FXF_CREAT | FXF_TRUNC | FXF_EXCL
WRITE_ACCESS = ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_WRITE_ATTRIBUTES
WRITE_DISPOSITIONS = {
    FXF_CREATE_NEW,
    FXF_CREATE_TRUNCATE,
    FXF_OPEN_OR_CREATE,
    FXF_TRUNCATE_EXISTING,
}


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int
    user: str
    root: Path
    host_key: Path
    authorized_keys: Optional[Path]
    password: Optional[str]
    read_only: bool
    allow_symlinks: bool
    allow_hardlinks: bool
    strict_path_check: bool
    max_upload_bytes: int
    login_timeout: int
    keepalive_interval: int
    keepalive_count_max: int
    disable_compression: bool


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _is_posix() -> bool:
    return os.name == "posix"


def _owned_by_current_user_or_root(path: Path) -> bool:
    if not _is_posix():
        return True

    st = path.stat()
    return st.st_uid in {os.getuid(), 0}


def _format_octal_mode(path: Path) -> str:
    return oct(_mode(path))


def validate_private_key_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()

    if path.expanduser().is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")

    if not resolved.exists():
        raise SystemExit(
            f"Missing {label}: {resolved}\n"
            f"Create one with:\n"
            f"  ssh-keygen -t ed25519 -f {resolved} -N \"\""
        )

    if not resolved.is_file():
        raise SystemExit(f"{label} is not a regular file: {resolved}")

    if _is_posix():
        if not _owned_by_current_user_or_root(resolved):
            raise SystemExit(f"{label} must be owned by the current user or root: {resolved}")

        if _mode(resolved) & 0o077:
            raise SystemExit(
                f"{label} is too permissive: {resolved} has mode "
                f"{_format_octal_mode(resolved)}; use chmod 600 {resolved}"
            )

    return resolved


def validate_authorized_keys(path: Optional[Path]) -> Optional[Path]:
    if path is None:
        return None

    resolved = path.expanduser().resolve()

    if path.expanduser().is_symlink():
        raise SystemExit(f"authorized_keys must not be a symlink: {path}")

    if not resolved.exists():
        raise SystemExit(f"Missing authorized_keys file: {resolved}")

    if not resolved.is_file():
        raise SystemExit(f"authorized_keys is not a regular file: {resolved}")

    if _is_posix():
        if not _owned_by_current_user_or_root(resolved):
            raise SystemExit(
                f"authorized_keys must be owned by the current user or root: {resolved}"
            )

        if _mode(resolved) & 0o022:
            raise SystemExit(
                f"authorized_keys must not be group/world writable: {resolved} "
                f"has mode {_format_octal_mode(resolved)}"
            )

    return resolved


def prepare_root(path: Path) -> Path:
    expanded = path.expanduser()

    if expanded.exists() and expanded.is_symlink():
        raise SystemExit(f"SFTP root must not be a symlink: {expanded}")

    resolved = expanded.resolve()
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)

    if not resolved.is_dir():
        raise SystemExit(f"SFTP root must be a directory: {resolved}")

    if _is_posix():
        if not _owned_by_current_user_or_root(resolved):
            raise SystemExit(f"SFTP root must be owned by current user or root: {resolved}")

        if _mode(resolved) & 0o022:
            raise SystemExit(
                f"SFTP root must not be group/world writable: {resolved} "
                f"has mode {_format_octal_mode(resolved)}"
            )

    return resolved


def is_local_bind_address(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def get_extra_info(obj: Any, name: str, default: Any = None) -> Any:
    getter = getattr(obj, "get_extra_info", None)
    if not getter:
        return default

    try:
        value = getter(name, default)
    except TypeError:
        value = getter(name)

    return default if value is None else value


def peer_to_ip(peername: Any) -> str:
    if isinstance(peername, tuple) and peername:
        return str(peername[0])
    if peername:
        return str(peername)
    return "unknown"


class LoginRateLimiter:
    """Small in-memory throttle for password authentication."""

    def __init__(self, max_failures: int, lockout_seconds: int) -> None:
        self.max_failures = max(1, max_failures)
        self.lockout_seconds = max(1, lockout_seconds)
        self._by_ip: dict[str, tuple[int, float]] = {}
        self._by_user: dict[tuple[str, str], tuple[int, float]] = {}

    @staticmethod
    def _is_locked(entry: Optional[tuple[int, float]], now: float) -> bool:
        if not entry:
            return False
        _, locked_until = entry
        return locked_until > now

    def blocked(self, ip: str, username: str) -> bool:
        now = time.monotonic()
        return self._is_locked(self._by_ip.get(ip), now) or self._is_locked(
            self._by_user.get((ip, username)), now
        )

    def record_failure(self, ip: str, username: str) -> None:
        now = time.monotonic()
        locked_until = now + self.lockout_seconds

        ip_count, ip_locked = self._by_ip.get(ip, (0, 0.0))
        user_count, user_locked = self._by_user.get((ip, username), (0, 0.0))

        ip_count = 0 if ip_locked <= now else ip_count
        user_count = 0 if user_locked <= now else user_count

        ip_count += 1
        user_count += 1

        self._by_ip[ip] = (
            ip_count,
            locked_until if ip_count >= self.max_failures else 0.0,
        )
        self._by_user[(ip, username)] = (
            user_count,
            locked_until if user_count >= self.max_failures else 0.0,
        )

    def record_success(self, ip: str, username: str) -> None:
        self._by_ip.pop(ip, None)
        self._by_user.pop((ip, username), None)


class HardenedSSHServer(asyncssh.SSHServer):
    def __init__(
        self,
        *,
        username: str,
        authorized_keys: Optional[Path],
        password: Optional[str],
        limiter: LoginRateLimiter,
    ) -> None:
        self.username = username
        self.authorized_keys = authorized_keys
        self.password = password
        self.limiter = limiter
        self.conn: Optional[asyncssh.SSHServerConnection] = None
        self.peer_ip = "unknown"
        self.auth_username = ""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        self.peer_ip = peer_to_ip(get_extra_info(conn, "peername"))
        LOG.info("SSH connection opened peer=%s", self.peer_ip)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            LOG.info("SSH connection closed peer=%s reason=%s", self.peer_ip, exc)
        else:
            LOG.info("SSH connection closed peer=%s", self.peer_ip)

    def begin_auth(self, username: str) -> bool:
        # IMPORTANT: Returning False here would accept the login with no auth.
        self.auth_username = username

        if (
            username == self.username
            and self.authorized_keys is not None
            and self.conn is not None
            and not self.limiter.blocked(self.peer_ip, username)
        ):
            self.conn.set_authorized_keys(str(self.authorized_keys))

        return True

    def public_key_auth_supported(self) -> bool:
        return (
            self.authorized_keys is not None
            and self.auth_username == self.username
            and not self.limiter.blocked(self.peer_ip, self.auth_username)
        )

    def password_auth_supported(self) -> bool:
        return (
            self.password is not None
            and self.auth_username == self.username
            and not self.limiter.blocked(self.peer_ip, self.auth_username)
        )

    def kbdint_auth_supported(self) -> bool:
        # Avoid keyboard-interactive falling back to password auth.
        return False

    def validate_password(self, username: str, password: str) -> bool:
        if self.limiter.blocked(self.peer_ip, username):
            LOG.warning("Auth blocked peer=%s username=%s", self.peer_ip, username)
            return False

        user_ok = hmac.compare_digest(username, self.username)
        password_ok = self.password is not None and hmac.compare_digest(password, self.password)

        if user_ok and password_ok:
            self.limiter.record_success(self.peer_ip, username)
            LOG.info("Password auth successful peer=%s username=%s", self.peer_ip, username)
            return True

        self.limiter.record_failure(self.peer_ip, username)
        LOG.warning("Password auth failed peer=%s username=%s", self.peer_ip, username)
        return False

    def auth_completed(self) -> None:
        self.limiter.record_success(self.peer_ip, self.auth_username)
        LOG.info("Auth successful peer=%s username=%s", self.peer_ip, self.auth_username)


class HardenedSFTPServer(asyncssh.SFTPServer):
    def __init__(
        self,
        chan: asyncssh.SSHServerChannel,
        *,
        chroot: str,
        username: str,
        read_only: bool,
        allow_symlinks: bool,
        allow_hardlinks: bool,
        strict_path_check: bool,
        max_upload_bytes: int,
    ) -> None:
        super().__init__(chan, chroot=chroot)
        self.username = username
        self.read_only = read_only
        self.allow_symlinks = allow_symlinks
        self.allow_hardlinks = allow_hardlinks
        self.strict_path_check = strict_path_check
        self.max_upload_bytes = max_upload_bytes
        self.root_real = Path(chroot).resolve()

    @staticmethod
    def _path_for_log(path: bytes) -> str:
        return os.fsdecode(path).replace("\n", "\\n").replace("\r", "\\r")

    def _deny_read_only(self) -> None:
        raise SFTPPermissionDenied("SFTP server is read-only")

    def _deny_unsupported(self, operation: str) -> None:
        raise SFTPOpUnsupported(f"{operation} is disabled by server policy")

    def _is_under_root(self, path: Path) -> bool:
        try:
            path.relative_to(self.root_real)
            return True
        except ValueError:
            return False

    def _validate_under_root(self, local_path: bytes) -> None:
        if not self.strict_path_check:
            return

        candidate = Path(os.fsdecode(local_path))

        # For new files, validate the parent. For existing files/symlinks,
        # validate the resolved target. This reduces symlink escape risk, but
        # OS-level isolation is still recommended for hostile users.
        check_path = candidate if candidate.exists() else candidate.parent
        resolved = check_path.resolve(strict=False)

        if not self._is_under_root(resolved):
            LOG.warning("Blocked path escape candidate=%s resolved=%s", candidate, resolved)
            raise SFTPPermissionDenied("Path escapes SFTP root")

    def map_path(self, path: bytes) -> bytes:
        local_path = super().map_path(path)
        self._validate_under_root(local_path)
        return local_path

    @staticmethod
    def _pflags_want_write(pflags: int) -> bool:
        return bool(pflags & WRITE_PFLAGS)

    @staticmethod
    def _open56_wants_write(desired_access: int, flags: int) -> bool:
        disp = flags & FXF_ACCESS_DISPOSITION
        return bool(
            desired_access & WRITE_ACCESS
            or flags & FXF_APPEND_DATA
            or disp in WRITE_DISPOSITIONS
        )

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs) -> object:
        write = self._pflags_want_write(pflags)
        if self.read_only and write:
            self._deny_read_only()

        requested_size = getattr(attrs, "size", None)
        if write and self.max_upload_bytes and requested_size and requested_size > self.max_upload_bytes:
            raise SFTPPermissionDenied("Upload exceeds max_upload_bytes")

        LOG.info(
            "SFTP open user=%s write=%s path=%s",
            self.username,
            write,
            self._path_for_log(path),
        )
        return super().open(path, pflags, attrs)

    def open56(
        self,
        path: bytes,
        desired_access: int,
        flags: int,
        attrs: asyncssh.SFTPAttrs,
    ) -> object:
        write = self._open56_wants_write(desired_access, flags)
        if self.read_only and write:
            self._deny_read_only()

        requested_size = getattr(attrs, "size", None)
        if write and self.max_upload_bytes and requested_size and requested_size > self.max_upload_bytes:
            raise SFTPPermissionDenied("Upload exceeds max_upload_bytes")

        LOG.info(
            "SFTP open56 user=%s write=%s path=%s",
            self.username,
            write,
            self._path_for_log(path),
        )
        return super().open56(path, desired_access, flags, attrs)

    def write(self, file_obj: object, offset: int, data: bytes) -> int:
        if self.read_only:
            self._deny_read_only()

        if self.max_upload_bytes and offset + len(data) > self.max_upload_bytes:
            raise SFTPPermissionDenied("Upload exceeds max_upload_bytes")

        return super().write(file_obj, offset, data)

    def setstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info("SFTP setstat user=%s path=%s", self.username, self._path_for_log(path))
        return super().setstat(path, attrs)

    def lsetstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info("SFTP lsetstat user=%s path=%s", self.username, self._path_for_log(path))
        return super().lsetstat(path, attrs)

    def fsetstat(self, file_obj: object, attrs: asyncssh.SFTPAttrs) -> None:
        if self.read_only:
            self._deny_read_only()
        return super().fsetstat(file_obj, attrs)

    def remove(self, path: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info("SFTP remove user=%s path=%s", self.username, self._path_for_log(path))
        return super().remove(path)

    def mkdir(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info("SFTP mkdir user=%s path=%s", self.username, self._path_for_log(path))
        return super().mkdir(path, attrs)

    def rmdir(self, path: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info("SFTP rmdir user=%s path=%s", self.username, self._path_for_log(path))
        return super().rmdir(path)

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info(
            "SFTP rename user=%s old=%s new=%s",
            self.username,
            self._path_for_log(oldpath),
            self._path_for_log(newpath),
        )
        return super().rename(oldpath, newpath)

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        LOG.info(
            "SFTP posix_rename user=%s old=%s new=%s",
            self.username,
            self._path_for_log(oldpath),
            self._path_for_log(newpath),
        )
        return super().posix_rename(oldpath, newpath)

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        if not self.allow_symlinks:
            self._deny_unsupported("symlink")
        LOG.info(
            "SFTP symlink user=%s old=%s new=%s",
            self.username,
            self._path_for_log(oldpath),
            self._path_for_log(newpath),
        )
        return super().symlink(oldpath, newpath)

    def link(self, oldpath: bytes, newpath: bytes) -> None:
        if self.read_only:
            self._deny_read_only()
        if not self.allow_hardlinks:
            self._deny_unsupported("hardlink")
        LOG.info(
            "SFTP hardlink user=%s old=%s new=%s",
            self.username,
            self._path_for_log(oldpath),
            self._path_for_log(newpath),
        )
        return super().link(oldpath, newpath)


def load_password(args: argparse.Namespace) -> Optional[str]:
    if not args.enable_password_auth:
        return None

    if args.password_file:
        password_path = validate_private_key_file(args.password_file, "password file")
        password = password_path.read_text(encoding="utf-8").splitlines()[0]
    else:
        password = os.getenv(args.password_env) if args.password_env else None

    if not password:
        password = getpass.getpass(f"Password for SFTP user '{args.user}': ")

    if len(password) < args.min_password_length:
        raise SystemExit(
            f"Password is too short. Minimum length is {args.min_password_length} characters."
        )

    return password


async def run_server(cfg: ServerConfig, args: argparse.Namespace) -> None:
    limiter = LoginRateLimiter(
        max_failures=args.max_auth_failures,
        lockout_seconds=args.lockout_seconds,
    )

    def server_factory() -> HardenedSSHServer:
        return HardenedSSHServer(
            username=cfg.user,
            authorized_keys=cfg.authorized_keys,
            password=cfg.password,
            limiter=limiter,
        )

    def sftp_factory(chan: asyncssh.SSHServerChannel) -> HardenedSFTPServer:
        username = get_extra_info(chan, "username", cfg.user)
        return HardenedSFTPServer(
            chan,
            chroot=str(cfg.root),
            username=str(username),
            read_only=cfg.read_only,
            allow_symlinks=cfg.allow_symlinks,
            allow_hardlinks=cfg.allow_hardlinks,
            strict_path_check=cfg.strict_path_check,
            max_upload_bytes=cfg.max_upload_bytes,
        )

    listen_kwargs: dict[str, Any] = {
        "server_factory": server_factory,
        "server_host_keys": [str(cfg.host_key)],
        "sftp_factory": sftp_factory,
        "allow_scp": False,
        "allow_pty": False,
        "line_editor": False,
        "x11_forwarding": False,
        "agent_forwarding": False,
        "gss_kex": False,
        "gss_auth": False,
        "login_timeout": cfg.login_timeout,
        "keepalive_interval": cfg.keepalive_interval,
        "keepalive_count_max": cfg.keepalive_count_max,
        "config": (),
    }

    if cfg.disable_compression:
        listen_kwargs["compression_algs"] = None

    listener = await asyncssh.listen(cfg.host, cfg.port, **listen_kwargs)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:  # pragma: no cover - Windows
            pass

    LOG.info("SFTP server listening host=%s port=%s", cfg.host, cfg.port)
    LOG.info("User=%s", cfg.user)
    LOG.info("Root=%s", cfg.root)
    LOG.info("Auth=%s", "public-key+password" if cfg.password else "public-key")
    LOG.info("Read-only=%s", cfg.read_only)

    try:
        await stop_event.wait()
    finally:
        listener.close()
        await listener.wait_closed()
        LOG.info("SFTP server stopped")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hardened lightweight Python SFTP server for Kali/Linux"
    )

    parser.add_argument("-p", "--port", type=int, default=2222)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Listen address. Non-localhost values require --allow-remote-listen.",
    )
    parser.add_argument(
        "--allow-remote-listen",
        action="store_true",
        help="Allow binding to non-loopback addresses such as 0.0.0.0.",
    )
    parser.add_argument("-r", "--root", type=Path, default=Path("./sftp-root"))
    parser.add_argument("-u", "--user", default="sftpuser")
    parser.add_argument(
        "--host-key",
        type=Path,
        default=Path("./ssh_host_ed25519_key"),
        help="SSH host private key path.",
    )
    parser.add_argument(
        "--authorized-keys",
        type=Path,
        help="OpenSSH authorized_keys file. Recommended and enabled by default.",
    )

    parser.add_argument(
        "--enable-password-auth",
        action="store_true",
        help="Enable password auth. Key auth remains recommended.",
    )
    parser.add_argument(
        "--password-env",
        default="SFTP_PASSWORD",
        help="Environment variable to read password from when password auth is enabled.",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Root/current-user owned chmod 600 file containing the password.",
    )
    parser.add_argument("--min-password-length", type=int, default=16)
    parser.add_argument("--max-auth-failures", type=int, default=5)
    parser.add_argument("--lockout-seconds", type=int, default=300)

    parser.add_argument("--read-only", action="store_true")
    parser.add_argument(
        "--allow-symlinks",
        action="store_true",
        help="Allow clients to create symlinks. Disabled by default.",
    )
    parser.add_argument(
        "--allow-hardlinks",
        action="store_true",
        help="Allow clients to create hardlinks. Disabled by default.",
    )
    parser.add_argument(
        "--no-strict-path-check",
        action="store_true",
        help="Disable realpath guard which reduces symlink escape risk.",
    )
    parser.add_argument(
        "--max-upload-bytes",
        type=int,
        default=0,
        help="Per-file upload limit. 0 means unlimited.",
    )

    parser.add_argument("--login-timeout", type=int, default=30)
    parser.add_argument("--keepalive-interval", type=int, default=30)
    parser.add_argument("--keepalive-count-max", type=int, default=3)
    parser.add_argument(
        "--enable-compression",
        action="store_true",
        help="Allow SSH compression. Disabled by default.",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Optional log file. Defaults to stderr.",
    )

    return parser.parse_args()


def configure_logging(args: argparse.Namespace) -> None:
    handlers: list[logging.Handler] = []

    if args.log_file:
        log_path = args.log_file.expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )

    # Keep AsyncSSH logs useful without enabling packet-level debug output.
    asyncssh.set_log_level(args.log_level)
    asyncssh.set_sftp_log_level(args.log_level)


def build_config(args: argparse.Namespace) -> ServerConfig:
    if not is_local_bind_address(args.host) and not args.allow_remote_listen:
        raise SystemExit(
            f"Refusing to bind to non-loopback address {args.host!r} without "
            "--allow-remote-listen"
        )

    if args.port < 1 or args.port > 65535:
        raise SystemExit("Port must be between 1 and 65535")

    if args.max_upload_bytes < 0:
        raise SystemExit("--max-upload-bytes cannot be negative")

    host_key = validate_private_key_file(args.host_key, "host key")
    authorized_keys = validate_authorized_keys(args.authorized_keys)
    password = load_password(args)

    if authorized_keys is None and password is None:
        raise SystemExit(
            "No authentication method configured. Provide --authorized-keys, "
            "or explicitly use --enable-password-auth."
        )

    if not is_local_bind_address(args.host) and password is not None:
        raise SystemExit(
            "Refusing remote password-auth service. Use public-key auth for "
            "remote listening, or bind to localhost."
        )

    root = prepare_root(args.root)

    return ServerConfig(
        host=args.host,
        port=args.port,
        user=args.user,
        root=root,
        host_key=host_key,
        authorized_keys=authorized_keys,
        password=password,
        read_only=args.read_only,
        allow_symlinks=args.allow_symlinks,
        allow_hardlinks=args.allow_hardlinks,
        strict_path_check=not args.no_strict_path_check,
        max_upload_bytes=args.max_upload_bytes,
        login_timeout=args.login_timeout,
        keepalive_interval=args.keepalive_interval,
        keepalive_count_max=args.keepalive_count_max,
        disable_compression=not args.enable_compression,
    )


def main() -> int:
    args = parse_args()
    configure_logging(args)

    if _is_posix():
        os.umask(0o077)

    cfg = build_config(args)

    try:
        asyncio.run(run_server(cfg, args))
        return 0
    except KeyboardInterrupt:
        LOG.info("Interrupted")
        return 0
    except asyncssh.Error as exc:
        LOG.error("AsyncSSH error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
