"""
C1 -- short-lived, scoped credential broker.

Instead of baking a permanent `DATABASE_URL` into a container, the broker mints a
per-run, scoped, short-TTL credential *after* the requesting workload proves its
identity (C2) and -- once C3 lands -- attests what it is. The workload receives an
ephemeral credential reference, not a long-lived secret.

What a Phase A credential is: a signed capability ticket (subject + project +
resource + scopes + issued/expiry + nonce), signed by the broker's issuer key. It
is verifiable and unforgeable, scope-limited to one bound resource, and expires on
its own. Redeeming a ticket for a real per-run datastore role at the managed
service is C5 (Phase B); this module establishes the identity->attest->issue spine
and the deny-by-default posture.

Trust model (single host): the broker is the issuer and, in Phase A, also the
verifier. It authenticates principals against a *trusted* `IdentityStore` keyed by
subject, so a requester can never pick the algorithm or key used to check it. With
the optional `cryptography` extra, the issuer key is Ed25519, so a Phase B managed
service can verify tickets with a public key it cannot use to forge.

Seam for later phases: `verify_token`/`authorize` are the redemption checks a
managed service (C5) will call; `issuer_public()` exposes the verify key to hand
out; attestation plugs into `issue()` via the `attestation`/`policy` hook (C3).
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from .audit import ATTEST_FAIL, DENY, ISSUE, VERIFY_FAIL
from .identity import HMAC_ALG, IdentityStore, Signer, default_signer, signer_for

DEFAULT_TTL = 900   # 15 minutes -- short enough to bound exposure, long enough to use
MAX_TTL = 3600      # hard ceiling: the short-TTL control cannot be opted out of

# Purpose tag mixed into ticket signatures (mirrors identity's proof tag) so a
# broker ticket can never be replayed as an identity proof, regardless of keys.
_TICKET_CONTEXT = b"perch-broker-ticket"


class BrokerDenied(Exception):
    """Issuance refused, fail-closed: identity unverified, request out of scope,
    bad TTL, or (C3) attestation mismatch."""


def _bounded_ttl(ttl) -> int:
    """Coerce and bound a TTL, failing closed on anything unusable."""
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        raise BrokerDenied(f"invalid ttl: {ttl!r} (expected a positive number of seconds)")
    seconds = int(ttl)
    if seconds <= 0 or seconds > MAX_TTL:
        raise BrokerDenied(f"ttl {seconds}s out of range (1..{MAX_TTL})")
    return seconds


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Claims:
    """The verified contents of a credential ticket."""
    subject: str
    project: str
    resource: str
    scopes: list[str]
    issued_at: int
    expires_at: int
    nonce: str

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at


@dataclass
class Credential:
    """A minted, short-lived, scoped credential. `token` is the wire form handed
    to the workload (an opaque ephemeral reference); the raw fields are kept for
    convenience and logging (none of them are secret -- the ticket is a signed
    capability, not a password)."""
    subject: str
    project: str
    resource: str
    scopes: list[str]
    issued_at: int
    expires_at: int
    nonce: str
    token: str

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def reference(self) -> str:
        """The value to inject into the workload's environment."""
        return self.token


class Broker:
    """Mints and verifies scoped, short-TTL credential tickets.

    `identities` is the trusted store used to authenticate requesters. Pass an
    `issuer_keypair` (alg, public, private) to use a persisted issuer key across
    runs; otherwise a fresh one is generated (and should be saved by the caller).
    `clock` is injectable for deterministic TTL tests.
    """

    def __init__(self, identities: IdentityStore, *,
                 issuer_keypair: "tuple[str, bytes, bytes] | None" = None,
                 alg: str | None = None,
                 default_ttl: int = DEFAULT_TTL,
                 attestor=None, audit=None, quarantine=None,
                 clock: Callable[[], float] = time.time):
        self.identities = identities
        self.default_ttl = _bounded_ttl(default_ttl)   # the default is bounded too
        self.attestor = attestor                       # C3: when set, issuance requires it
        self.audit = audit                             # C11: optional tamper-evident sink
        self.quarantine = quarantine                   # C11: subjects to refuse
        self.clock = clock
        if issuer_keypair is not None:
            self.alg, self._issuer_public, self._issuer_private = issuer_keypair
            self.signer: Signer = signer_for(self.alg)
        else:
            self.signer = default_signer() if alg is None else signer_for(alg)
            self.alg = self.signer.alg
            self._issuer_public, self._issuer_private = self.signer.keypair()

    # ---- key access (persist / hand out the verify key) -----------------
    def issuer_keypair(self) -> "tuple[str, bytes, bytes]":
        """(alg, public, private) -- persist this so tickets stay verifiable."""
        return self.alg, self._issuer_public, self._issuer_private

    def issuer_public(self) -> "tuple[str, bytes]":
        """(alg, public) -- the verify key a managed service (C5) would hold.

        Refuses for the symmetric HMAC backend, where the "public" key IS the
        signing secret: handing it out would let the holder forge tickets. An
        exportable verify key requires the asymmetric (Ed25519) issuer, i.e. the
        optional `cryptography` extra."""
        if self.alg == HMAC_ALG:
            raise BrokerDenied(
                "HMAC issuer has no exportable verify key (it would be the signing "
                "secret); install the `cryptography` extra for an Ed25519 issuer")
        return self.alg, self._issuer_public

    def _now(self, now: float | None) -> int:
        return int(self.clock() if now is None else now)

    # ---- issuance (deny-by-default) -------------------------------------
    def issue(self, subject: str, resource: str, *, challenge: bytes, proof: bytes,
              scopes: list[str] | None = None, ttl: int | None = None,
              now: float | None = None, attestation=None) -> Credential:
        """Issue a credential for `subject` to use `resource`. Requires a valid
        identity proof (signature over `challenge`) and that the principal is
        scoped for `resource`. If this broker has an attestor configured (C3), a
        matching `attestation` for `subject` is also required -- absent or
        mismatched, issuance is denied, closed."""
        if not isinstance(subject, str) or len(subject) > 256:
            raise BrokerDenied("invalid subject")   # bound the audit-chain entry
        # 0. quarantine (C11): a flagged subject is refused outright
        if self.quarantine is not None and subject in self.quarantine:
            self._audit(DENY, subject, f"quarantined; requested {resource!r}", now)
            raise BrokerDenied(f"{subject!r} is quarantined")
        # 1. authenticate the principal against the TRUSTED store
        if not self.identities.verify(subject, challenge, proof):
            self._audit(VERIFY_FAIL, subject, f"requested {resource!r}", now)
            raise BrokerDenied(f"identity verification failed for {subject!r}")
        ident = self.identities.get(subject)
        # 2. scope: the principal must be authorized for this resource
        if resource not in (ident.scopes or []):
            self._audit(DENY, subject, f"out of scope for {resource!r}", now)
            raise BrokerDenied(f"{subject!r} is not scoped for resource {resource!r}")
        # 3. attestation (C3): the instance must be what we expect, deny on mismatch
        if self.attestor is not None:
            if attestation is None or attestation.subject != subject or not self.attestor.verify(attestation):
                self._audit(ATTEST_FAIL, subject, f"resource {resource!r}", now)
                raise BrokerDenied(f"attestation failed for {subject!r}")
        # 4. mint a short-TTL, scoped ticket (TTL is bounded; bad values deny)
        iat = self._now(now)
        exp = iat + (self.default_ttl if ttl is None else _bounded_ttl(ttl))
        scopes = list(scopes) if scopes is not None else [f"{resource}:connect"]
        nonce = secrets.token_urlsafe(12)
        payload = {"sub": subject, "prj": ident.project, "res": resource,
                   "scp": scopes, "iat": iat, "exp": exp, "nonce": nonce}
        token = self._sign(payload)
        self._audit(ISSUE, subject, f"resource {resource!r} ttl={exp - iat}s", now)
        return Credential(subject, ident.project, resource, scopes, iat, exp, nonce, token)

    def _audit(self, kind: str, subject: str, detail: str, now: float | None) -> None:
        if self.audit is not None:
            self.audit.record(kind, subject, detail, at=self._now(now))

    def _sign(self, payload: dict) -> str:
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = self.signer.sign(self._issuer_private, _TICKET_CONTEXT + b"\x00" + msg)
        return _b64u(msg) + "." + _b64u(sig)

    # ---- verification / redemption (what C5 services will call) ---------
    def verify_token(self, token: str, *, now: float | None = None) -> Claims | None:
        """Validate signature and expiry. Returns Claims, or None (fail-closed)
        on a bad/expired/tampered/quarantined token."""
        try:
            msg_b64, sig_b64 = token.split(".", 1)
            msg, sig = _b64u_dec(msg_b64), _b64u_dec(sig_b64)
        except (ValueError, TypeError, binascii.Error):
            return None
        if not self.signer.verify(self._issuer_public, _TICKET_CONTEXT + b"\x00" + msg, sig):
            return None
        try:
            p = json.loads(msg)
            claims = Claims(p["sub"], p["prj"], p["res"], list(p["scp"]),
                            int(p["iat"]), int(p["exp"]), p["nonce"])
        except (ValueError, KeyError, TypeError):
            return None
        if claims.is_expired(self._now(now)):
            return None
        # C11: a quarantined subject's outstanding ticket is revoked immediately,
        # not just blocked at next issuance.
        if self.quarantine is not None and claims.subject in self.quarantine:
            return None
        return claims

    def authorize(self, token: str, resource: str, scope: str | None = None, *,
                  now: float | None = None) -> bool:
        """True iff `token` is a valid, unexpired ticket for `resource` (and, if
        given, grants `scope`). Everything else is a closed deny."""
        claims = self.verify_token(token, now=now)
        if claims is None:
            return False
        if claims.resource != resource:
            return False
        if scope is not None and scope not in claims.scopes:
            return False
        return True
