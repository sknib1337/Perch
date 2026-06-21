"""
C2 -- per-agent cryptographic identity.

Every workload gets a stable subject identifier and a freshly generated key at
provision time. It can sign a challenge; a verifier (the credential broker, C1)
checks the signature before issuing anything. No long-lived service secret is
needed to prove who a workload is.

Identities are *self-describing*: each carries the algorithm it was issued under,
and a verifier selects the scheme from the identity record, never from the
signature. Downgrade-resistance therefore depends on the record being TRUSTED:
verify against an identity you stored at issuance, not one a requester hands you.
`IdentityStore.verify(subject, ...)` is the safe entry point -- it looks the record
up by subject from trusted storage, so a caller can never dictate the algorithm or
key used to check them (this is the structural defense against an Ed25519->HMAC
downgrade, where a published public key would otherwise double as an HMAC secret).
The low-level `verify(identity, ...)` trusts whatever record it is given; only pass
it records from trusted storage. As defense in depth, signed bytes are domain
separated by both algorithm and purpose: identity proofs are tagged
`perch-identity-proof`, so a proof can never be reinterpreted as a broker ticket
(C1), and a tag minted under one algorithm cannot validate under another.

Crypto backend (hybrid, opt-in upgrade -- no hard dependency):
  - default            HMAC-SHA256 from the standard library. Symmetric: the
                       verifier holds the same secret as the signer, which fits a
                       single-host control plane that is both issuer and verifier.
  - cryptography extra Ed25519 keypairs, so the broker verifies with a PUBLIC key
                       it cannot use to forge. Used automatically when the optional
                       `cryptography` package is importable.
  - PERCH_CRYPTO_BACKEND=stdlib forces the stdlib backend even if `cryptography`
                       is installed (operational kill-switch and test hook).

Seam for later phases: `Signer` is a Protocol and identities dispatch by `alg`,
so additional schemes (HSM/KMS-backed, X.509) drop in without touching callers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol, runtime_checkable

HMAC_ALG = "hmac-sha256"
ED25519_ALG = "ed25519"

# Verification material shorter than this is never produced by keypair() (32-byte
# keys); treat anything shorter as a corrupt/degenerate record and fail closed.
_MIN_KEY_BYTES = 32


def _domain(alg: str, message: bytes) -> bytes:
    """Bind a message to the algorithm signing it (domain separation), so a tag
    produced under one scheme cannot be replayed/forged as valid under another."""
    return alg.encode("ascii") + b"\x00" + message


def _stdlib_forced() -> bool:
    return os.environ.get("PERCH_CRYPTO_BACKEND", "").strip().lower() == "stdlib"


try:  # optional asymmetric upgrade -- never a hard dependency
    if _stdlib_forced():
        raise ImportError("PERCH_CRYPTO_BACKEND=stdlib")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _HAVE_ED25519 = True
except Exception:  # noqa: BLE001 -- absence or force => stdlib path, fail safe
    _HAVE_ED25519 = False


class UnknownAlgorithm(ValueError):
    """An identity names a signing algorithm this install cannot service.

    Raised (rather than silently failing verification) so that a deployment
    error -- e.g. an Ed25519 identity on a host without the `cryptography`
    extra -- is loud instead of masquerading as an authentication failure.
    """


# ---- signing backends ---------------------------------------------------
@runtime_checkable
class Signer(Protocol):
    alg: str

    def keypair(self) -> tuple[bytes, bytes]:
        """Return (public, private). For symmetric backends public == private."""
        ...

    def sign(self, private: bytes, message: bytes) -> bytes: ...

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        """Constant-time / fail-closed. Never raises on bad signature input."""
        ...


class HmacSigner:
    """HMAC-SHA256. Symmetric -- the verification material IS the secret, so an
    HMAC identity's `public_key` must be sealed at rest (see C4) and never
    exposed by the API."""

    alg = HMAC_ALG

    def keypair(self) -> tuple[bytes, bytes]:
        key = secrets.token_bytes(_MIN_KEY_BYTES)
        return key, key

    def sign(self, private: bytes, message: bytes) -> bytes:
        if len(private) < _MIN_KEY_BYTES:
            raise ValueError("HMAC key too short")
        return hmac.new(private, _domain(self.alg, message), hashlib.sha256).digest()

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        if len(public) < _MIN_KEY_BYTES:   # degenerate/empty key -> fail closed
            return False
        expected = hmac.new(public, _domain(self.alg, message), hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


class Ed25519Signer:
    """Ed25519. Asymmetric -- `public_key` is safe to publish; the broker can
    verify without being able to forge."""

    alg = ED25519_ALG

    def keypair(self) -> tuple[bytes, bytes]:
        sk = Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()

    def sign(self, private: bytes, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(private).sign(_domain(self.alg, message))

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, _domain(self.alg, message))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


_SIGNERS: dict[str, Signer] = {HMAC_ALG: HmacSigner()}
if _HAVE_ED25519:
    _SIGNERS[ED25519_ALG] = Ed25519Signer()


def default_signer() -> Signer:
    """Best available backend: Ed25519 if present, else stdlib HMAC."""
    return _SIGNERS[ED25519_ALG] if _HAVE_ED25519 else _SIGNERS[HMAC_ALG]


def signer_for(alg: str) -> Signer:
    if not isinstance(alg, str):
        raise UnknownAlgorithm(f"algorithm must be a string, got {type(alg).__name__}")
    try:
        return _SIGNERS[alg]
    except (KeyError, TypeError):
        raise UnknownAlgorithm(
            f"no signer for algorithm '{alg}' "
            f"(known: {sorted(_SIGNERS)}; is the `cryptography` extra installed?)"
        ) from None


def available_signers() -> list[Signer]:
    """All usable backends in this install (handy for exhaustive tests)."""
    return list(_SIGNERS.values())


# ---- principals & identities --------------------------------------------
@dataclass
class Principal:
    """Who is asking. `scopes` are the resources/permissions this principal may
    request from the broker (e.g. bound managed-service names)."""

    subject: str
    kind: str                      # agent | webapp | function | operator | ...
    project: str
    scopes: list[str] = field(default_factory=list)


def subject_for(project: str, name: str, kind: str = "workload") -> str:
    """Stable, namespaced, human-readable subject id (SPIFFE-ish). Stable across
    re-provisions of the same workload even when its key rotates."""
    return f"perch://{project}/{kind}/{name}"


@dataclass(repr=False)
class Identity:
    """The verifiable, storable identity record. Holds NO private key.

    For Ed25519, `public_key` is a true public key (safe to expose). For HMAC it
    is the shared secret used to verify -- treat it as sensitive, seal it at
    rest, and never return it from the API. `public_key_is_secret` flags which.

    `__repr__` is overridden to redact the secret-bearing HMAC `public_key`, so a
    stray log line or traceback can't leak it.
    """

    subject: str
    kind: str
    project: str
    scopes: list[str]
    alg: str
    public_key: str = field(repr=False)   # hex; secret for HMAC -- never auto-repr'd
    created_at: int

    @property
    def public_key_is_secret(self) -> bool:
        return self.alg == HMAC_ALG

    def __repr__(self) -> str:
        pk = "<sealed>" if self.public_key_is_secret else self.public_key
        return (f"Identity(subject={self.subject!r}, kind={self.kind!r}, "
                f"project={self.project!r}, alg={self.alg!r}, public_key={pk!r})")

    def redacted(self) -> dict:
        """Display form: never leaks HMAC verification secrets."""
        d = asdict(self)
        if self.public_key_is_secret:
            d["public_key"] = "<sealed>"
        return d

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Identity":
        return Identity(
            subject=d["subject"], kind=d["kind"], project=d["project"],
            scopes=list(d.get("scopes", [])), alg=d["alg"],
            public_key=d["public_key"], created_at=int(d["created_at"]),
        )


@dataclass(repr=False)
class IssuedIdentity:
    """Result of issuance: the public record plus the private signing key.

    `signing_key` is the workload's secret. Hand it to the workload and/or seal
    it (C4); never persist it in cleartext. Only `identity` is meant for storage.
    `__repr__` never renders the key material.
    """

    identity: Identity
    signing_key: bytes = field(repr=False)

    def __repr__(self) -> str:
        return (f"IssuedIdentity(identity={self.identity!r}, "
                f"signing_key=<{len(self.signing_key)} bytes>)")


# ---- the three operations the brief asks for ----------------------------
def issue(principal: Principal, signer: Signer | None = None, *,
          clock: Callable[[], float] = time.time) -> IssuedIdentity:
    """Issue an identity for `principal`: generate a key and bind it to a record."""
    signer = signer or default_signer()
    public, private = signer.keypair()
    ident = Identity(
        subject=principal.subject, kind=principal.kind, project=principal.project,
        scopes=list(principal.scopes), alg=signer.alg,
        public_key=public.hex(), created_at=int(clock()),
    )
    return IssuedIdentity(identity=ident, signing_key=private)


def new_challenge(nbytes: int = 32) -> bytes:
    """A fresh random challenge for a sign/verify handshake."""
    return secrets.token_bytes(nbytes)


# Purpose tag mixed into identity-proof signatures so they can never be replayed
# as broker tickets (which use their own tag), independent of key disjointness.
_PROOF_CONTEXT = b"perch-identity-proof"


def _proof_message(challenge: bytes) -> bytes:
    return _PROOF_CONTEXT + b"\x00" + bytes(challenge)


def sign(identity: Identity, signing_key: bytes, challenge: bytes) -> bytes:
    """Sign `challenge` as `identity` using its private signing key."""
    return signer_for(identity.alg).sign(signing_key, _proof_message(challenge))


def verify(identity: Identity, challenge: bytes, signature: bytes) -> bool:
    """Low-level primitive: True iff `signature` is valid for `challenge` under
    `identity`. TRUSTS the record it is given -- it selects the algorithm and key
    from `identity`, so only ever pass a record from trusted storage. To verify a
    request from a (semi-trusted) workload, use `IdentityStore.verify`, which
    looks the trusted record up by subject and so cannot be downgraded by the
    requester.

    Returns False on any authentic failure (wrong key, tampered challenge or
    signature, malformed inputs). Raises `UnknownAlgorithm` only when the
    identity's algorithm is unsupported here -- a deployment error, not a
    forgery -- so it surfaces loudly instead of looking like a bad password.
    """
    signer = signer_for(identity.alg)   # may raise UnknownAlgorithm (deliberate)
    if not isinstance(challenge, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return False
    try:
        public = bytes.fromhex(identity.public_key)
    except (ValueError, TypeError):
        return False
    return signer.verify(public, _proof_message(challenge), bytes(signature))


# ---- trusted identity registry ------------------------------------------
class IdentityStore:
    """Trusted registry of issued identities, keyed by subject.

    This is the SECURE verification entry point. Because it looks the record up
    by subject from storage Perch controls, a requester can never dictate the
    algorithm or key used to check them -- which is what structurally closes the
    Ed25519->HMAC downgrade (a forged record never reaches the verifier).

    Holds only public identity records. For HMAC identities the stored
    `public_key` is the verification secret, so persist this store sealed (C4)
    and never expose it through the API. Serialization helpers are provided so a
    later phase can persist it via `State`.
    """

    def __init__(self, records: dict[str, Identity] | None = None):
        self._by_subject: dict[str, Identity] = dict(records or {})

    def put(self, identity: Identity) -> None:
        self._by_subject[identity.subject] = identity

    def register(self, issued: IssuedIdentity) -> IssuedIdentity:
        """Store the public record from an issuance; returns it unchanged so the
        caller still holds the private signing key to hand to the workload."""
        self.put(issued.identity)
        return issued

    def get(self, subject: str) -> Identity | None:
        return self._by_subject.get(subject)

    def __contains__(self, subject: str) -> bool:
        return subject in self._by_subject

    def verify(self, subject: str, challenge: bytes, signature: bytes) -> bool:
        """True iff `signature` proves possession of `subject`'s key over
        `challenge`. Unknown subject -> False (fail closed)."""
        ident = self._by_subject.get(subject)
        if ident is None:
            return False
        return verify(ident, challenge, signature)

    def to_dict(self) -> dict:
        return {s: i.to_dict() for s, i in self._by_subject.items()}

    @staticmethod
    def from_dict(d: dict) -> "IdentityStore":
        return IdentityStore({s: Identity.from_dict(v) for s, v in (d or {}).items()})
