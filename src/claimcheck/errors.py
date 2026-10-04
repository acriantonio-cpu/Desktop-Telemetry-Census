"""Exception hierarchy. The CLI turns these into clean messages (no traceback) unless --debug."""


class ClaimCheckError(Exception):
    """Base class for expected, user-facing errors."""

    hint: str = ""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        if hint:
            self.hint = hint


class ManifestError(ClaimCheckError):
    """The app manifest is missing, unreadable or invalid."""


class RunError(ClaimCheckError):
    """A run directory cannot be created / found / opened."""


class RunLocked(RunError):
    """Another live process is working on the same run."""


class PreconditionError(ClaimCheckError):
    """A phase was launched without what it needs (e.g. no install_dir)."""


class CaptureError(ClaimCheckError):
    """Dynamic capture could not start or failed."""
