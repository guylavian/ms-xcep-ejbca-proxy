"""
Cache backend interface.

Defines the protocol for cache implementations (Redis, in-memory, etc.)
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class CacheBackend(Protocol):
    """
    Protocol for cache backends.

    Implementations should provide methods for:
    - Basic get/set operations
    - Policy response caching
    - Health checks
    """

    @property
    def available(self) -> bool:
        """
        Check if cache is available.

        Returns:
            True if cache is operational, False otherwise
        """
        ...

    def get(self, key: str) -> Optional[bytes]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        ...

    def set(self, key: str, value: bytes, ttl: int = 300) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds

        Returns:
            True if successful, False otherwise
        """
        ...

    def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if deleted, False if not found
        """
        ...

    def get_policy_response(self, client_identity: str, groups_hash: str) -> Optional[bytes]:
        """
        Get cached policy response.

        Args:
            client_identity: Client principal
            groups_hash: Hash of user's group memberships

        Returns:
            Cached SOAP response or None
        """
        ...

    def set_policy_response(self, client_identity: str, response: bytes,
                            groups_hash: str, ttl: int = 300) -> bool:
        """
        Cache policy response.

        Args:
            client_identity: Client principal
            response: SOAP response to cache
            groups_hash: Hash of user's group memberships
            ttl: Time-to-live in seconds

        Returns:
            True if successful
        """
        ...
