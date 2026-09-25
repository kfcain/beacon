"""Process and thread safe, reentrant workspace serialization."""
from functools import wraps
from contextlib import contextmanager

from filelock import FileLock, Timeout

from beacon.errors import BeaconError


@contextmanager
def workspace_lock(settings):
    settings.home.mkdir(parents=True, exist_ok=True)
    with FileLock(str(settings.home / ".workspace.lock"), timeout=120, is_singleton=True):
        if settings.anchor_dir is not None:
            root = settings.anchor_dir.resolve()
            if root == settings.home.resolve() or root.is_relative_to(settings.home.resolve()):
                raise BeaconError("E_CONTINUITY", "external anchor directory must be outside the workspace")
            root.mkdir(parents=True, exist_ok=True)
            with FileLock(str(root / ".anchor.lock"), timeout=120, is_singleton=True):
                yield
        else:
            yield


def locked(function):
    @wraps(function)
    def run(settings, *args, **kwargs):
        try:
            with workspace_lock(settings):
                return function(settings, *args, **kwargs)
        except Timeout as exc:
            raise BeaconError("E_BUSY", "workspace is busy; retry after the active operation") from exc
    return run
