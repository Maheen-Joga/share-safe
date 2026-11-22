"""share-safe: make logs, configs and error messages safe to share."""

from .redactor import Hit, Options, find

__all__ = ["Hit", "Options", "find"]
__version__ = "0.1.0"
