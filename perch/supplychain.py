"""
C12 -- supply-chain integrity.

C3 attests an instance's config and build identity; C12 adds the cryptographic
artifact identity, so only a pinned, allow-listed image runs. A workload opts in:

    verify:
      pin: true                         # image must be pinned to a @sha256 digest
      registries: [ghcr.io, docker.io]  # and pulled only from these registries

A mutable tag (`:latest`) can change under you between pull and run; a digest can't.
Pairing `verify: {pin: true}` with `identity:` is the strongest posture -- a fixed
artifact running under a per-run identity.

This module is the pure parser + policy (offline-tested). Re-verifying the *actual*
pulled digest against the pin (vs. the declared ref alone) is a backend hook (the
glue that resolves a running image's digest); the static ref policy is enforced at
apply time regardless.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_REGISTRY = "docker.io"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass
class ImageRef:
    registry: str
    repo: str
    tag: "str | None"
    digest: "str | None"
    raw: str

    @property
    def pinned(self) -> bool:
        # A real pin is a full sha256:<64 hex> -- 'sha256:' or a short value is not.
        return bool(self.digest) and bool(_SHA256_RE.match(self.digest))


def parse_image(ref: str) -> ImageRef:
    """Parse `[registry/]repo[:tag][@sha256:...]`. The first path segment is the
    registry only if it looks like a host (contains '.' or ':' or is 'localhost'),
    matching Docker's own rule; otherwise the default registry is assumed."""
    raw = ref
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    registry, rest = DEFAULT_REGISTRY, ref
    if "/" in ref:
        first, tail = ref.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            registry, rest = first, tail
    tag = None
    if ":" in rest:                       # a ':' here is a tag (registry port already split off)
        rest, tag = rest.rsplit(":", 1)
    return ImageRef(registry=registry, repo=rest, tag=tag, digest=digest, raw=raw)


@dataclass
class DigestPolicy:
    require_pinned: bool = False
    allow_registries: "list | None" = None     # None => any registry

    def check(self, image: "str | None") -> "tuple[bool, str]":
        """Verify a declared image ref against the policy. A service with no image
        (built locally) passes -- its provenance is the build source hash (C3)."""
        if not image:
            return (True, "built locally; provenance via source hash")
        ref = parse_image(image)
        if self.require_pinned and not ref.pinned:
            if ref.digest is not None:        # a typo'd/short digest fails closed, not "unpinned"
                return (False, f"image {image!r} has a malformed digest (need sha256:<64 hex>)")
            return (False, f"image {image!r} is not pinned to a @sha256 digest")
        if self.allow_registries is not None and ref.registry not in self.allow_registries:
            return (False, f"registry {ref.registry!r} is not in the allowlist {self.allow_registries}")
        return (True, "ok")

    def check_actual(self, image: "str | None", actual_digest: str) -> "tuple[bool, str]":
        """Strongest check: the pulled image's actual digest must equal the pin."""
        ok, reason = self.check(image)
        if not ok:
            return (ok, reason)
        ref = parse_image(image) if image else None
        if ref and ref.pinned:
            if not actual_digest:             # backend couldn't resolve it -> fail closed
                return (False, f"could not resolve pulled digest to verify pin {ref.digest!r}")
            if ref.digest != actual_digest:
                return (False, f"pulled digest {actual_digest!r} != pinned {ref.digest!r}")
        return (True, "ok")
