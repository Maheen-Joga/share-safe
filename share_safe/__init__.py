"""share-safe: make logs, configs and error messages safe to share."""

from .redactor import Hit, Options, Result, find, redact, restore

__all__ = ["Hit", "Options", "Result", "find", "redact", "restore"]
__version__ = "0.1.0"
