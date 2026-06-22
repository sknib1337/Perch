# The control-plane convenience names. These pull in pyyaml (via manifest) and the
# rest of the package; the C9 gateway sidecar (perch/gateway.py) runs on a minimal
# python image that has only the stdlib, so guard these so importing the stdlib-only
# submodules (perch.gateway/mcp/mediation) still works where an optional dep is absent.
try:
    from .backend import Backend, LiveService, ManagedSpec, RenderContext
    from .docker_backend import DockerBackend
    from .manifest import Build, EnvVar, Manifest, Route, Service, MANAGED_TYPES
    from .reconcile import Action, Reconciler
    from .state import State

    __all__ = [
        "Backend", "LiveService", "ManagedSpec", "RenderContext", "DockerBackend",
        "Build", "EnvVar", "Manifest", "Route", "Service", "MANAGED_TYPES",
        "Action", "Reconciler", "State",
    ]
except ModuleNotFoundError:          # minimal env (the gateway sidecar): optional deps absent
    __all__ = []
__version__ = "0.3.0"
