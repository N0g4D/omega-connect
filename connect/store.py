"""The app's own store: per-swarm server list, encrypted credentials, call traces.

Layout under OMEGA_CONNECT_DATA_DIR (default ~/.omega-connect), one folder per
swarm (named by a digest of the swarm id):

    servers.json   server records, no secrets; each keeps the tools a person
                   accepted as read, with the digest of the definition accepted
    secrets.bin    OAuth tokens, each person's own, and which one the swarm's
                   minds use; encrypted with Fernet (AES-128-CBC + HMAC)
    trace.jsonl    one line per tool call: digests only, never content; cut
                   to its newest half once it passes 1 MiB
    intents.bin    app-level idempotency records for use-tool, each with the
                   answer it gave, encrypted with Fernet like the tokens; cut
                   to the newest half once they pass 1 MiB

The encryption key comes from OMEGA_CONNECT_SECRET_KEY (a Fernet key). Without
it the store refuses to keep credentials or use-tool's records: it fails closed
rather than writing tokens or tool results in clear. Files are created with
mode 0600, and every write is flushed to disk before it is relied on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

SERVER_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
CRED_VARIABLE = re.compile(r"^OMEGA_CONNECT_CRED_[A-Z0-9_]{1,60}$")
# trace.jsonl is cut to its newest half once it grows past this, so a view, which reads it whole,
# reads at most this much however many calls the swarm has made.
TRACE_MAX_BYTES = 1 << 20
# use-tool's records (intents.bin) are cut the same way, measured before encryption.
INTENTS_MAX_BYTES = 1 << 20
INTENTS = "use-tool's records"  # what _fernet() names when it cannot keep them


class StoreError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def digest(value: Any) -> str:
    """sha256 of canonical JSON (or of the text itself for strings)."""
    if isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _base_dir() -> Path:
    return Path(os.environ.get("OMEGA_CONNECT_DATA_DIR") or Path.home() / ".omega-connect")


def _write_private(path: Path, data: bytes) -> None:
    """Write the file whole or not at all: a temporary file flushed to disk, renamed over the old
    one, then the folder flushed, so after a crash the file is the old one or the new one."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    _fsync_folder(path.parent)


def _fsync_folder(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fernet(what: str = "credentials"):
    key = os.environ.get("OMEGA_CONNECT_SECRET_KEY", "").strip()
    if not key:
        raise StoreError("no_secret_key",
                         f"the operator has not set OMEGA_CONNECT_SECRET_KEY, so {what} cannot be stored")
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise StoreError("no_crypto", f"the 'cryptography' package is required to store {what}")
    try:
        return Fernet(key.encode("ascii"))
    except Exception:
        raise StoreError("bad_secret_key", "OMEGA_CONNECT_SECRET_KEY is not a valid Fernet key")


class SwarmStore:
    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, swarm_id: str):
        if not swarm_id:
            raise StoreError("no_swarm", "every call must be scoped to a swarm")
        self.swarm_id = str(swarm_id)
        folder = hashlib.sha256(self.swarm_id.encode("utf-8")).hexdigest()[:24]
        self.dir = _base_dir() / folder
        with SwarmStore._locks_guard:
            self.lock = SwarmStore._locks.setdefault(folder, threading.Lock())

    # ---------------------------------------------------------- servers
    def servers(self) -> dict[str, dict]:
        path = self.dir / "servers.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text("utf-8")).get("servers", {})

    def _save_servers(self, servers: dict[str, dict]) -> None:
        payload = {"swarm": digest(self.swarm_id), "servers": servers}
        _write_private(self.dir / "servers.json", json.dumps(payload, indent=2, sort_keys=True).encode())

    def put_server(self, record: dict) -> None:
        with self.lock:
            servers = self.servers()
            servers[record["name"]] = record
            self._save_servers(servers)

    def remove_server(self, name: str) -> bool:
        with self.lock:
            servers = self.servers()
            if servers.pop(name, None) is None:
                return False
            self._save_servers(servers)
        self.delete_credentials(name)
        return True

    def set_tool_class(self, server: str, tool: str, cls: str | None) -> None:
        with self.lock:
            servers = self.servers()
            record = servers.get(server)
            if record is None:
                raise StoreError("unknown_server", f"no server named '{server}'")
            reclass = record.setdefault("reclass", {})
            if cls is None:
                reclass.pop(tool, None)
            else:
                reclass[tool] = cls
            self._save_servers(servers)

    def accept_reads(self, server: str, digests: dict[str, str], by: str, whole_server: bool) -> None:
        """Record that a person accepted these tools as read: {tool: digest of its definition}.
        For the whole server the list replaces the earlier one."""
        with self.lock:
            servers = self.servers()
            record = servers.get(server)
            if record is None:
                raise StoreError("unknown_server", f"no server named '{server}'")
            reviewed = {} if whole_server else record.get("reviewed", {})
            at = int(time.time())
            reviewed.update({tool: {"digest": value, "by": by, "at": at} for tool, value in digests.items()})
            record["reviewed"] = reviewed
            self._save_servers(servers)

    # ---------------------------------------------------------- credentials
    def _secrets(self) -> dict:
        path = self.dir / "secrets.bin"
        if not path.exists():
            return {}
        return json.loads(_fernet().decrypt(path.read_bytes()).decode("utf-8"))

    def _save_secrets(self, secrets: dict) -> None:
        token = _fernet().encrypt(json.dumps(secrets).encode("utf-8"))
        _write_private(self.dir / "secrets.bin", token)

    # Each person signs in for themselves: secrets.bin holds, per server,
    # {"people": {principal: token}, "minds": principal or None}, "minds" naming the sign-in the
    # swarm's minds use.
    @staticmethod
    def _signins(secrets: dict, server: str) -> dict:
        entry = secrets.get(server)
        if not isinstance(entry, dict) or not isinstance(entry.get("people"), dict):
            # None yet, or the one sign-in per server of 0.2.0, which names no principal: it counts
            # as none, and its person signs in again.
            entry = {"people": {}, "minds": None}
        return entry

    def signins(self, server: str) -> dict:
        """{"people": {principal: token}, "minds": principal or None} for `server`."""
        with self.lock:
            return self._signins(self._secrets(), server)

    def credentials(self, server: str, principal: str | None) -> dict | None:
        """The sign-in of one person (by principal) to `server`."""
        with self.lock:
            return self._signins(self._secrets(), server)["people"].get(principal) if principal else None

    def put_credentials(self, server: str, principal: str, value: dict, for_minds: bool = False) -> None:
        """Keep a person's sign-in; with for_minds, it is also the one the swarm's minds use."""
        with self.lock:
            secrets = self._secrets()
            entry = secrets[server] = self._signins(secrets, server)
            entry["people"][principal] = value
            if for_minds:
                entry["minds"] = principal
            self._save_secrets(secrets)

    def lend(self, server: str, principal: str) -> bool:
        """Make a person's sign-in the one the swarm's minds use, in place of any other; False if they
        have none."""
        with self.lock:
            secrets = self._secrets()
            entry = self._signins(secrets, server)
            if principal not in entry["people"]:
                return False
            entry["minds"] = principal
            secrets[server] = entry
            self._save_secrets(secrets)
            return True

    def replace_credentials(self, server: str, principal: str, old: dict, new: dict) -> bool:
        """Store `new` only if the person's stored credentials are still `old`, so a renewal that
        finishes after a revoke or a new sign-in never writes over them."""
        with self.lock:
            secrets = self._secrets()
            entry = secrets[server] = self._signins(secrets, server)
            if entry["people"].get(principal) != old:
                return False
            entry["people"][principal] = new
            self._save_secrets(secrets)
            return True

    def delete_credentials(self, server: str, principal: str | None = None) -> bool:
        """Delete one person's sign-in to `server` (minds stop using it if they did), or with no
        principal every sign-in to it."""
        with self.lock:
            path = self.dir / "secrets.bin"
            if not path.exists():
                return False
            secrets = self._secrets()
            if principal is None:
                removed = secrets.pop(server, None) is not None
            else:
                entry = secrets[server] = self._signins(secrets, server)
                removed = entry["people"].pop(principal, None) is not None
                if entry["minds"] == principal:
                    entry["minds"] = None
            self._save_secrets(secrets)
            return removed

    def has_credentials(self, server: str, principal: str | None = None) -> bool:
        """Whether this person, or with no principal anyone, is signed in to `server`."""
        try:
            people = self.signins(server)["people"]
        except StoreError:
            return False
        return bool(people) if principal is None else principal in people

    # ---------------------------------------------------------- traces
    def trace(self, entry: dict) -> None:
        entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **entry}
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
        with self.lock:
            path = self.dir / "trace.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
                size = os.fstat(handle.fileno()).st_size
            if size > TRACE_MAX_BYTES:
                # Keep the newest half: a trim costs one rewrite per half a limit of new lines.
                lines = path.read_bytes().splitlines(keepends=True)
                kept, total = [], 0
                for raw in reversed(lines):
                    total += len(raw)
                    if total > TRACE_MAX_BYTES // 2:
                        break
                    kept.append(raw)
                _write_private(path, b"".join(reversed(kept)))

    def traces(self, limit: int = 30) -> list[dict]:
        path = self.dir / "trace.jsonl"
        if not path.exists():
            return []
        lines = path.read_text("utf-8").splitlines()[-max(limit, 0):]
        return [json.loads(line) for line in lines if line.strip()]

    def trace_mark(self) -> str:
        """Changes with every line traced, also after a trim: the number of lines and the last one."""
        path = self.dir / "trace.jsonl"
        if not path.exists():
            return ""
        lines = path.read_bytes().splitlines()
        return f"{len(lines)}:{digest(lines[-1].decode('utf-8')) if lines else ''}"

    # ---------------------------------------------------------- intents
    # use-tool's own records keep each answer whole, what the tool sent back included, so they are
    # encrypted with the tokens' key.
    def _intents(self) -> dict:
        """The records, decrypted. A plain intents.json left by an earlier version is moved into the
        encrypted file and deleted, so no tool result stays on disk in clear."""
        path, plain = self.dir / "intents.bin", self.dir / "intents.json"
        data = {}
        if path.exists():
            fernet = _fernet(INTENTS)
            try:
                data = json.loads(fernet.decrypt(path.read_bytes()).decode("utf-8"))
            except Exception:  # cryptography's InvalidToken: written with another key
                raise StoreError("bad_secret_key", f"{INTENTS} cannot be read with this OMEGA_CONNECT_SECRET_KEY")
        if plain.exists():
            data = {**json.loads(plain.read_text("utf-8")), **data}
            self._save_intents(data)
            plain.unlink()
            _fsync_folder(self.dir)
        return data

    def _save_intents(self, data: dict) -> None:
        """Past INTENTS_MAX_BYTES the records are cut to the newest that fit in half of it, as the
        trace is; the newest one always stays."""
        sizes = {key: len(json.dumps({key: record}, sort_keys=True)) for key, record in data.items()}
        if sum(sizes.values()) > INTENTS_MAX_BYTES:
            kept, total = {}, 0
            for key in sorted(data, key=lambda k: data[k].get("at", 0), reverse=True):
                total += sizes[key]
                if kept and total > INTENTS_MAX_BYTES // 2:
                    break
                kept[key] = data[key]
            data = kept
        _write_private(self.dir / "intents.bin",
                       _fernet(INTENTS).encrypt(json.dumps(data, sort_keys=True).encode("utf-8")))

    def intent(self, key: str) -> dict | None:
        with self.lock:
            return self._intents().get(key)

    def put_intent(self, key: str, record: dict) -> None:
        with self.lock:
            data = self._intents()
            data[key] = record
            self._save_intents(data)

    def drop_intent(self, key: str) -> None:
        with self.lock:
            data = self._intents()
            if data.pop(key, None) is not None:
                self._save_intents(data)
