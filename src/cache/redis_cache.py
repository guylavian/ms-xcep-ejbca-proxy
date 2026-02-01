"""
Redis caching layer for certificate enrollment proxy.

Caches GetPolicies responses and other expensive operations
to reduce load on LDAP and EJBCA backends.
"""

import json
import logging
import hashlib
import time
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Any, Callable, Union, Protocol, runtime_checkable
from functools import wraps

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

logger = logging.getLogger(__name__)


class CacheError(Exception):
    """Cache operation error."""
    pass


@dataclass
class CacheConfig:
    """Cache configuration."""

    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None

    # Connection pool settings
    max_connections: int = 10
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0

    # Default TTLs (in seconds)
    default_ttl: int = 3600  # 1 hour
    policy_ttl: int = 7200   # 2 hours for GetPolicies responses
    template_ttl: int = 14400  # 4 hours for AD template info
    ca_info_ttl: int = 86400   # 24 hours for CA information

    # Key prefixes
    key_prefix: str = "xcep_proxy"

    # Enable/disable cache
    enabled: bool = True

    # Compression threshold (bytes) - compress responses larger than this
    compression_threshold: int = 1024

    # Availability check interval (seconds) - don't ping Redis on every call
    availability_check_interval: float = 5.0

    # Stampede protection lock TTL (seconds)
    lock_ttl: int = 10


# Key component delimiter - prevents key collisions
KEY_DELIMITER = ":"


@runtime_checkable
class CacheBackend(Protocol):
    """
    Protocol defining the cache interface.

    Both RedisCache and MemoryCache implement this protocol,
    ensuring they are interchangeable.
    """

    @property
    def available(self) -> bool:
        """Check if cache is available."""
        ...

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        ...

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL."""
        ...

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        ...

    def clear_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern."""
        ...

    def get_policy_response(self, client_identity: str,
                            groups_hash: str = None) -> Optional[bytes]:
        """Get cached GetPolicies response."""
        ...

    def set_policy_response(self, client_identity: str, response: bytes,
                            groups_hash: str = None) -> bool:
        """Cache GetPolicies response."""
        ...

    def invalidate_policy_cache(self, client_identity: str = None) -> int:
        """Invalidate policy cache."""
        ...


class BaseCacheBackend(ABC):
    """
    Abstract base class for cache backends.

    Provides common functionality for key generation, compression,
    and serialization. Subclasses implement storage-specific operations.
    """

    # Key type prefixes
    KEY_POLICY = "policy"
    KEY_TEMPLATE = "template"
    KEY_CA = "ca"
    KEY_USER = "user"
    KEY_LOCK = "lock"

    def __init__(self, config: CacheConfig):
        self.config = config

    def _make_key(self, *parts) -> str:
        """
        Create a cache key from parts with consistent delimiter.

        Uses KEY_DELIMITER between all parts to prevent collisions.
        Example: xcep_proxy:policy:abc123:default
        """
        all_parts = [self.config.key_prefix]
        all_parts.extend(str(p) for p in parts if p is not None)
        return KEY_DELIMITER.join(all_parts)

    def _hash_key(self, data: str) -> str:
        """Create a hash of data for use in keys."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _compress(self, data: bytes) -> bytes:
        """Compress data if above threshold."""
        if len(data) > self.config.compression_threshold:
            compressed = zlib.compress(data, level=6)
            # Only use compressed if it's actually smaller
            if len(compressed) < len(data):
                return b"Z" + compressed  # Prefix to indicate compression
        return b"R" + data  # Raw/uncompressed

    def _decompress(self, data: bytes) -> bytes:
        """Decompress data if it was compressed."""
        if not data:
            return data
        if data[0:1] == b"Z":
            return zlib.decompress(data[1:])
        elif data[0:1] == b"R":
            return data[1:]
        # Legacy data without prefix
        return data

    def _serialize(self, value: Any) -> str:
        """Serialize value for storage."""
        return json.dumps(value, default=self._json_serializer)

    def _deserialize(self, data: str) -> Any:
        """Deserialize value from storage."""
        return json.loads(data)

    @staticmethod
    def _json_serializer(obj):
        """Custom JSON serializer for objects not serializable by default."""
        if isinstance(obj, datetime):
            return {"__datetime__": obj.isoformat()}
        if isinstance(obj, bytes):
            import base64
            return {"__bytes__": base64.b64encode(obj).decode("ascii")}
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    # Abstract methods to be implemented by subclasses

    @property
    @abstractmethod
    def available(self) -> bool:
        """Check if cache is available."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        pass

    @abstractmethod
    def clear_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern."""
        pass

    # Common high-level cache operations

    def get_policy_response(self, client_identity: str,
                            groups_hash: str = None) -> Optional[bytes]:
        """Get cached GetPolicies response."""
        cache_key = self._make_key(
            self.KEY_POLICY,
            self._hash_key(client_identity),
            groups_hash or "default"
        )
        result = self._get_raw(cache_key)
        if result:
            return self._decompress(result)
        return None

    def set_policy_response(self, client_identity: str, response: bytes,
                            groups_hash: str = None) -> bool:
        """Cache GetPolicies response with compression."""
        cache_key = self._make_key(
            self.KEY_POLICY,
            self._hash_key(client_identity),
            groups_hash or "default"
        )
        compressed = self._compress(response)
        return self._set_raw(cache_key, compressed, self.config.policy_ttl)

    def invalidate_policy_cache(self, client_identity: str = None) -> int:
        """Invalidate policy cache."""
        if client_identity:
            pattern = self._make_key(self.KEY_POLICY, self._hash_key(client_identity), "*")
        else:
            pattern = self._make_key(self.KEY_POLICY, "*")
        return self.clear_pattern(pattern)

    # Template cache operations

    def get_templates(self) -> Optional[list]:
        """Get cached certificate templates."""
        key = self._make_key(self.KEY_TEMPLATE, "all")
        return self.get(key)

    def set_templates(self, templates: list) -> bool:
        """Cache certificate templates."""
        key = self._make_key(self.KEY_TEMPLATE, "all")
        return self.set(key, templates, self.config.template_ttl)

    def get_template(self, template_name: str) -> Optional[dict]:
        """Get cached template by name."""
        key = self._make_key(self.KEY_TEMPLATE, template_name.lower())
        return self.get(key)

    def set_template(self, template_name: str, template: dict) -> bool:
        """Cache template by name."""
        key = self._make_key(self.KEY_TEMPLATE, template_name.lower())
        return self.set(key, template, self.config.template_ttl)

    def invalidate_templates(self) -> int:
        """Invalidate all template cache."""
        return self.clear_pattern(self._make_key(self.KEY_TEMPLATE, "*"))

    # CA cache operations

    def get_ca_info(self, ca_name: str) -> Optional[dict]:
        """Get cached CA information."""
        key = self._make_key(self.KEY_CA, ca_name.lower())
        return self.get(key)

    def set_ca_info(self, ca_name: str, ca_info: dict) -> bool:
        """Cache CA information."""
        key = self._make_key(self.KEY_CA, ca_name.lower())
        return self.set(key, ca_info, self.config.ca_info_ttl)

    def get_ca_list(self) -> Optional[list]:
        """Get cached list of CAs."""
        key = self._make_key(self.KEY_CA, "list")
        return self.get(key)

    def set_ca_list(self, cas: list) -> bool:
        """Cache list of CAs."""
        key = self._make_key(self.KEY_CA, "list")
        return self.set(key, cas, self.config.ca_info_ttl)

    # User cache operations

    def get_user_groups(self, principal: str) -> Optional[list]:
        """Get cached user group memberships."""
        key = self._make_key(self.KEY_USER, self._hash_key(principal), "groups")
        return self.get(key)

    def set_user_groups(self, principal: str, groups: list,
                        ttl: int = 1800) -> bool:
        """Cache user group memberships (shorter TTL for security)."""
        key = self._make_key(self.KEY_USER, self._hash_key(principal), "groups")
        return self.set(key, groups, ttl)

    # Raw bytes operations (for compressed data)

    @abstractmethod
    def _get_raw(self, key: str) -> Optional[bytes]:
        """Get raw bytes from cache."""
        pass

    @abstractmethod
    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        """Set raw bytes in cache."""
        pass


class RedisCache(BaseCacheBackend):
    """
    Redis-based caching for the enrollment proxy.

    Features:
    - Connection pooling
    - Compression for large responses
    - SCAN-based pattern deletion (O(1) per iteration)
    - Cached availability checks
    - Stampede protection via SETNX locks
    """

    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self._client: Optional[redis.Redis] = None
        self._last_available_check: float = 0
        self._last_available_result: bool = False

        if config.enabled and REDIS_AVAILABLE:
            self._connect()

    def _connect(self) -> None:
        """Connect to Redis server."""
        try:
            pool = redis.ConnectionPool(
                host=self.config.host,
                port=self.config.port,
                db=self.config.db,
                password=self.config.password,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                decode_responses=False  # We handle encoding ourselves
            )
            self._client = redis.Redis(connection_pool=pool)

            # Test connection
            self._client.ping()
            self._last_available_result = True
            self._last_available_check = time.time()
            logger.info(f"Connected to Redis at {self.config.host}:{self.config.port}")

        except (redis.RedisError, Exception) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._client = None
            self._last_available_result = False

    @property
    def available(self) -> bool:
        """
        Check if cache is available.

        Caches the result to avoid ping overhead on every call.
        """
        if not self.config.enabled or not REDIS_AVAILABLE or not self._client:
            return False

        # Use cached result if recent enough
        now = time.time()
        if now - self._last_available_check < self.config.availability_check_interval:
            return self._last_available_result

        try:
            self._client.ping()
            self._last_available_result = True
        except redis.RedisError:
            self._last_available_result = False

        self._last_available_check = now
        return self._last_available_result

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.available:
            return None
        try:
            value = self._client.get(key)
            if value:
                return self._deserialize(value.decode("utf-8"))
            return None
        except (redis.RedisError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL."""
        if not self.available:
            return False
        try:
            ttl = ttl or self.config.default_ttl
            serialized = self._serialize(value)
            self._client.setex(key, ttl, serialized.encode("utf-8"))
            return True
        except (redis.RedisError, TypeError) as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        if not self.available:
            return False
        try:
            self._client.delete(key)
            return True
        except redis.RedisError as e:
            logger.warning(f"Cache delete error for {key}: {e}")
            return False

    def clear_pattern(self, pattern: str) -> int:
        """
        Delete keys matching pattern using SCAN.

        Uses scan_iter() instead of keys() to avoid blocking Redis.
        Deletes in batches for efficiency.
        """
        if not self.available:
            return 0
        try:
            count = 0
            batch = []
            batch_size = 100

            for key in self._client.scan_iter(match=pattern, count=100):
                batch.append(key)
                if len(batch) >= batch_size:
                    self._client.delete(*batch)
                    count += len(batch)
                    batch = []

            # Delete remaining keys
            if batch:
                self._client.delete(*batch)
                count += len(batch)

            return count
        except redis.RedisError as e:
            logger.warning(f"Cache clear pattern error for {pattern}: {e}")
            return 0

    def _get_raw(self, key: str) -> Optional[bytes]:
        """Get raw bytes from cache."""
        if not self.available:
            return None
        try:
            return self._client.get(key)
        except redis.RedisError as e:
            logger.warning(f"Cache get_raw error for {key}: {e}")
            return None

    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        """Set raw bytes in cache."""
        if not self.available:
            return False
        try:
            self._client.setex(key, ttl, value)
            return True
        except redis.RedisError as e:
            logger.warning(f"Cache set_raw error for {key}: {e}")
            return False

    def acquire_lock(self, lock_name: str, ttl: int = None) -> bool:
        """
        Acquire a distributed lock for stampede protection.

        Args:
            lock_name: Name of the lock
            ttl: Lock TTL in seconds

        Returns:
            True if lock acquired, False otherwise
        """
        if not self.available:
            return True  # Allow operation if cache unavailable

        ttl = ttl or self.config.lock_ttl
        key = self._make_key(self.KEY_LOCK, lock_name)
        try:
            # SETNX returns True if key was set (lock acquired)
            return bool(self._client.set(key, "1", nx=True, ex=ttl))
        except redis.RedisError:
            return True  # Allow operation on error

    def release_lock(self, lock_name: str) -> bool:
        """Release a distributed lock."""
        key = self._make_key(self.KEY_LOCK, lock_name)
        return self.delete(key)


class MemoryCache(BaseCacheBackend):
    """
    Simple in-memory cache fallback when Redis is not available.

    Uses a dict with TTL tracking. Not suitable for production
    multi-process deployments but useful for:
    - Development/testing
    - Single-process deployments
    - Fallback when Redis is temporarily unavailable

    Implements the same interface as RedisCache for compatibility.
    """

    def __init__(self, config: CacheConfig = None):
        super().__init__(config or CacheConfig(enabled=True))
        self._cache: dict = {}
        self._expiry: dict = {}
        self._raw_cache: dict = {}  # For raw bytes storage
        self._raw_expiry: dict = {}

    @property
    def available(self) -> bool:
        """Always available if enabled."""
        return self.config.enabled

    def _cleanup_expired(self) -> None:
        """Remove expired entries."""
        now = datetime.now()

        # Cleanup regular cache
        expired = [k for k, exp in self._expiry.items() if now > exp]
        for key in expired:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)

        # Cleanup raw cache
        expired_raw = [k for k, exp in self._raw_expiry.items() if now > exp]
        for key in expired_raw:
            self._raw_cache.pop(key, None)
            self._raw_expiry.pop(key, None)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.available:
            return None

        # Check expiry
        if key in self._expiry:
            if datetime.now() > self._expiry[key]:
                del self._cache[key]
                del self._expiry[key]
                return None

        return self._cache.get(key)

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache."""
        if not self.available:
            return False

        ttl = ttl or self.config.default_ttl
        self._cache[key] = value
        self._expiry[key] = datetime.now() + timedelta(seconds=ttl)

        # Periodic cleanup (every 100 sets)
        if len(self._cache) % 100 == 0:
            self._cleanup_expired()

        return True

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        self._cache.pop(key, None)
        self._expiry.pop(key, None)
        self._raw_cache.pop(key, None)
        self._raw_expiry.pop(key, None)
        return True

    def clear_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern (glob-style with *)."""
        import fnmatch

        count = 0

        # Clear from regular cache
        keys_to_delete = [k for k in self._cache.keys() if fnmatch.fnmatch(k, pattern)]
        for key in keys_to_delete:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)
            count += 1

        # Clear from raw cache
        raw_keys_to_delete = [k for k in self._raw_cache.keys() if fnmatch.fnmatch(k, pattern)]
        for key in raw_keys_to_delete:
            self._raw_cache.pop(key, None)
            self._raw_expiry.pop(key, None)
            count += 1

        return count

    def _get_raw(self, key: str) -> Optional[bytes]:
        """Get raw bytes from cache."""
        if not self.available:
            return None

        if key in self._raw_expiry:
            if datetime.now() > self._raw_expiry[key]:
                del self._raw_cache[key]
                del self._raw_expiry[key]
                return None

        return self._raw_cache.get(key)

    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        """Set raw bytes in cache."""
        if not self.available:
            return False

        self._raw_cache[key] = value
        self._raw_expiry[key] = datetime.now() + timedelta(seconds=ttl)
        return True

    def acquire_lock(self, lock_name: str, ttl: int = None) -> bool:
        """Acquire lock (always succeeds in single-process memory cache)."""
        return True

    def release_lock(self, lock_name: str) -> bool:
        """Release lock (no-op in memory cache)."""
        return True


# Type alias for cache instances
CacheInstance = Union[RedisCache, MemoryCache]


def create_cache(config: CacheConfig) -> CacheInstance:
    """
    Create cache instance based on configuration.

    Falls back to MemoryCache if Redis is not available.
    Both implementations share the same interface (BaseCacheBackend).

    Args:
        config: Cache configuration

    Returns:
        RedisCache if Redis is available, otherwise MemoryCache
    """
    if config.enabled and REDIS_AVAILABLE:
        cache = RedisCache(config)
        if cache.available:
            return cache
        logger.warning("Redis not available, falling back to memory cache")

    return MemoryCache(config)


def cached(cache: CacheInstance, key_func: Callable, ttl: int = None):
    """
    Decorator for caching function results.

    Args:
        cache: Cache instance (RedisCache or MemoryCache)
        key_func: Function to generate cache key from args
        ttl: Cache TTL in seconds

    Usage:
        @cached(cache, lambda name: f"template:{name}", ttl=3600)
        def get_template(name: str) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not cache.available:
                return func(*args, **kwargs)

            # Generate cache key
            cache_key = cache._make_key("func", key_func(*args, **kwargs))

            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return result

            # Call function and cache result
            result = func(*args, **kwargs)
            if result is not None:
                cache.set(cache_key, result, ttl or cache.config.default_ttl)

            return result
        return wrapper
    return decorator


def cached_with_lock(cache: CacheInstance, key_func: Callable,
                     ttl: int = None, lock_ttl: int = 10):
    """
    Decorator for caching with stampede protection.

    If multiple requests arrive for the same uncached key simultaneously,
    only one will compute the value while others wait or return stale data.

    Args:
        cache: Cache instance
        key_func: Function to generate cache key from args
        ttl: Cache TTL in seconds
        lock_ttl: Lock TTL in seconds
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not cache.available:
                return func(*args, **kwargs)

            cache_key = cache._make_key("func", key_func(*args, **kwargs))
            lock_key = f"lock:{key_func(*args, **kwargs)}"

            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result

            # Try to acquire lock
            if hasattr(cache, 'acquire_lock') and not cache.acquire_lock(lock_key, lock_ttl):
                # Another process is computing, wait a bit and retry cache
                time.sleep(0.1)
                result = cache.get(cache_key)
                if result is not None:
                    return result
                # Still no result, compute anyway (fallback)

            try:
                result = func(*args, **kwargs)
                if result is not None:
                    cache.set(cache_key, result, ttl or cache.config.default_ttl)
                return result
            finally:
                if hasattr(cache, 'release_lock'):
                    cache.release_lock(lock_key)

        return wrapper
    return decorator
