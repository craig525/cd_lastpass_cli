class InvalidLastpassClientParams(Exception):
    """Raised when a LastPass client cannot be created."""


class NoSavedCredentials(Exception):
    """Raised when persisted LastPass credentials are unavailable."""
