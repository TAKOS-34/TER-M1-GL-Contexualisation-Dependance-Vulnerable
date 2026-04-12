"""Custom exception hierarchy."""


class VulnerabilityError(Exception):
    """Base exception for vulnerability-related errors."""
    pass


class SourceError(VulnerabilityError):
    """Raised when a vulnerability source fails."""
    def __init__(self, source: str, message: str, retryable: bool = True):
        self.source = source
        self.message = message
        self.retryable = retryable
        super().__init__(f"[{source}] {message}")


class SourceTimeoutError(SourceError):
    """Raised when a source times out."""
    def __init__(self, source: str, timeout: float):
        super().__init__(source, f"Timeout after {timeout}s", retryable=True)


class SourceConnectionError(SourceError):
    """Raised when connection to source fails."""
    def __init__(self, source: str, details: str = ""):
        super().__init__(source, f"Connection failed: {details}", retryable=True)


class SourceNotFoundError(SourceError):
    """Raised when resource not found in source."""
    def __init__(self, source: str, resource: str):
        super().__init__(source, f"{resource} not found", retryable=False)


class CacheError(VulnerabilityError):
    """Raised when cache operations fail."""
    pass


class ValidationError(VulnerabilityError):
    """Raised when data validation fails."""
    pass


class CPEError(ValidationError):
    """Raised when CPE parsing/validation fails."""
    pass


class VersionError(ValidationError):
    """Raised when version comparison fails."""
    pass
