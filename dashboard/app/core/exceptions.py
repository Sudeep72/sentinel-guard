"""Exception types shared by the service layer.

Both the REST API layer and the MCP layer catch these and translate
them into their respective response formats (HTTP status codes for
REST, structured error dicts for MCP) — but the exceptions themselves
are raised from one place: the services in ``app/services/``. This is
what keeps "the AI asked" and "the human clicked a button" behaviorally
identical on the error path too, not just the happy path.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for all service-layer errors."""


class NotFoundError(ServiceError):
    """Raised when a requested resource (server, scan, finding, ...) doesn't exist."""


class ConflictError(ServiceError):
    """Raised when an operation would violate a uniqueness/state constraint."""


class AuthenticationError(ServiceError):
    """Raised when credentials (user password, agent API key) are invalid."""


class ValidationFailedError(ServiceError):
    """Raised when input passes contract validation but fails a business rule."""
