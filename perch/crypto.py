"""
C4 -- sealed secrets at rest.

Envelope-encrypts Perch's state so that copying `.perch/state.json` yields
ciphertext and a scheme tag, not credentials. This protects the highest-value
material: managed-service passwords, the broker issuer signing key, and any HMAC
identity verification secrets (see THREAT_MODEL C4).

Pluggable, hybrid, opt-in -- no hard dependency and no behavior change unless a
key is configured:
  - default            stdlib only. A `Sealer` derives per-message keys with HKDF
                       (RFC 5869 over HMAC-SHA256), encrypts with an HMAC-CTR
                       keystream, and authenticates with encrypt-then-MAC and a
                       constant-time tag check. Scheme tag `PSL1`.
  - cryptography extra Fernet (AES-128-CBC + HMAC). Scheme tag `PSF1`.
  - PERCH_CRYPTO_BACKEND=stdlib forces the stdlib scheme even if Fernet is present.

Every sealed blob is self-describing (`<scheme>.<body>`), so `unseal` dispatches to
the right implementation and a Fernet-sealed blob is never fed to the stdlib path.

Key provider: the master key comes from `$PERCH_MASTER_KEY` (use high-entropy
material, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`) or a
key file (`.perch/master.key` -- 0600 on POSIX; on Windows it inherits the parent
directory ACL, since chmod cannot set POSIX bits there). A key shorter than 16
bytes is rejected. Absent both sources, no sealer exists and state stays cleartext
-- exactly the prior behavior. External KMS/HSM providers plug in by supplying a
master key (or replacing `Sealer`) without touching `State`.

Seam for later phases: `default_sealer()` is the single place key sourcing lives;
swap it for a KMS-backed provider and the rest of the system is unchanged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path

MASTER_KEY_ENV = "PERCH_MASTER_KEY"
_MIN_KEY_BYTES = 16   # reject trivially weak / passphrase-typo master keys
_LOCAL_SCHEME = "PSL1"
_FERNET_SCHEME = "PSF1"
_KEYSTREAM_INFO = b"perch-seal-v1"
_FERNET_INFO = b"perch-seal-fernet-v1"


def _stdlib_forced() -> bool:
    return os.environ.get("PERCH_CRYPTO_BACKEND", "").strip().lower() == "stdlib"


try:
    if _stdlib_forced():
        raise ImportError("PERCH_CRYPTO_BACKEND=stdlib")
    from cryptography.fernet import Fernet, InvalidToken
    _HAVE_FERNET = True
except Exception:  # noqa: BLE001 -- absence or force => stdlib path
    _HAVE_FERNET = False


class SealError(Exception):
    """Sealing/unsealing failed: wrong/absent key, unknown scheme, or a tampered
    (authentication-failed) blob. Always fail closed -- never return plaintext."""


# ---- primitives (stdlib only) -------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hkdf(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869): extract-then-expand."""
    prk = hmac.new(salt, key, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _keystream(enc_key: bytes, n: int) -> bytes:
    """HMAC-SHA256 in counter mode -> a keystream of `n` bytes."""
    out, counter = b"", 0
    while len(out) < n:
        out += hmac.new(enc_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def is_sealed(blob: str) -> bool:
    """True if `blob` carries a recognized seal scheme tag."""
    return isinstance(blob, str) and blob[:5] in (_LOCAL_SCHEME + ".", _FERNET_SCHEME + ".")


# ---- the sealer ---------------------------------------------------------
class Sealer:
    """Seals/unseals bytes with a master key. Seals using the best available
    scheme (Fernet if present, else stdlib); unseals ANY known scheme by tag, so
    blobs written before/after installing the `cryptography` extra still open."""

    def __init__(self, master_key: bytes, prefer_fernet: bool | None = None):
        if not master_key:
            raise SealError("empty master key")
        key = master_key if isinstance(master_key, bytes) else str(master_key).encode()
        if len(key) < _MIN_KEY_BYTES:
            raise SealError(
                f"master key too short ({len(key)} bytes); need >= {_MIN_KEY_BYTES} "
                f"bytes of high-entropy material -- generate one with "
                f'`python -c "import secrets; print(secrets.token_urlsafe(32))"`')
        self._key = key
        self._prefer_fernet = _HAVE_FERNET if prefer_fernet is None else (prefer_fernet and _HAVE_FERNET)

    # -- public API --
    def seal(self, data: "bytes | str") -> str:
        pt = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        return self._seal_fernet(pt) if self._prefer_fernet else self._seal_local(pt)

    def unseal(self, token: str) -> bytes:
        scheme, _, body = (token or "").partition(".")
        if scheme == _LOCAL_SCHEME:
            return self._unseal_local(body)
        if scheme == _FERNET_SCHEME:
            return self._unseal_fernet(body)
        raise SealError(f"unknown seal scheme {scheme!r}")

    def unseal_str(self, token: str) -> str:
        return self.unseal(token).decode("utf-8")

    # -- stdlib scheme (PSL1): HKDF -> HMAC-CTR keystream + encrypt-then-MAC --
    def _seal_local(self, pt: bytes) -> str:
        nonce = secrets.token_bytes(16)
        enc_key, mac_key = self._derive(nonce)
        ct = _xor(pt, _keystream(enc_key, len(pt)))
        tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        return f"{_LOCAL_SCHEME}." + _b64u(nonce + ct + tag)

    def _unseal_local(self, body: str) -> bytes:
        try:
            raw = _b64u_dec(body)
        except (binascii.Error, ValueError):
            raise SealError("malformed sealed blob") from None
        if len(raw) < 16 + 32:                       # nonce + tag, ciphertext may be empty
            raise SealError("truncated sealed blob")
        nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
        enc_key, mac_key = self._derive(nonce)
        expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):   # authenticate before decrypt
            raise SealError("authentication failed (wrong key or tampered blob)")
        return _xor(ct, _keystream(enc_key, len(ct)))

    def _derive(self, nonce: bytes) -> tuple[bytes, bytes]:
        okm = _hkdf(self._key, nonce, _KEYSTREAM_INFO, 64)
        return okm[:32], okm[32:]                     # (enc_key, mac_key)

    # -- Fernet scheme (PSF1) --
    def _fernet(self) -> "Fernet":
        fkey = base64.urlsafe_b64encode(_hkdf(self._key, b"perch-fernet", _FERNET_INFO, 32))
        return Fernet(fkey)

    def _seal_fernet(self, pt: bytes) -> str:
        return f"{_FERNET_SCHEME}." + self._fernet().encrypt(pt).decode("ascii")

    def _unseal_fernet(self, body: str) -> bytes:
        if not _HAVE_FERNET:
            raise SealError("blob sealed with Fernet but the `cryptography` extra is not installed")
        try:
            token = body.encode("ascii")
        except UnicodeEncodeError:
            raise SealError("malformed sealed blob") from None
        try:
            return self._fernet().decrypt(token)
        except (InvalidToken, ValueError, binascii.Error):
            raise SealError("authentication failed (wrong key or tampered blob)") from None


# ---- key sourcing (the pluggable provider) ------------------------------
def _read_key_file(p: Path) -> str:
    """Read a key file, refusing one that is group/other-readable on POSIX (a
    0600 key is the documented contract; reading a 0644 key would be a silent
    downgrade). On Windows, permissions are governed by the directory ACL."""
    if os.name == "posix":
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            raise SealError(
                f"{p} has insecure permissions {oct(mode)}; expected 0600 "
                f"(fix with: chmod 600 {p})")
    return p.read_text().strip()


def master_key_from_env(env=None) -> "bytes | None":
    v = (env or os.environ).get(MASTER_KEY_ENV)
    return v.encode("utf-8") if v else None


def master_key_from_file(root: str = ".perch") -> "bytes | None":
    p = Path(root) / "master.key"
    if p.exists():
        data = _read_key_file(p)
        return data.encode("utf-8") if data else None
    return None


def ensure_local_key(root: str = ".perch") -> bytes:
    """Create a 0600 `.perch/master.key` if absent (explicit opt-in to sealing),
    and return its material. Created atomically with restrictive permissions so
    no secret bytes ever touch a world-readable file (0600 on POSIX; Windows uses
    the directory ACL). Does nothing destructive if one already exists."""
    p = Path(root) / "master.key"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, _b64u(secrets.token_bytes(32)).encode("ascii"))
            finally:
                os.close(fd)
        except FileExistsError:
            pass                                  # created concurrently; just read it
    return _read_key_file(p).encode("utf-8")


def default_sealer(root: str = ".perch", env=None) -> "Sealer | None":
    """Return a Sealer iff a master key is configured (env var or key file). With
    neither, returns None and state stays cleartext -- the prior behavior."""
    key = master_key_from_env(env) or master_key_from_file(root)
    return Sealer(key) if key else None
