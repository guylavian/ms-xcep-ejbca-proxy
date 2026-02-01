"""
Redis caching layer for certificate enrollment proxy.

Caches GetPolicies responses and other expensive operations
to reduce load on LDAP and EJBCA backends.
"""

import json
import logging
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional, Any, Callable
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
    """Redis cache configuration."""

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
    key_prefix: str = "xcep_proxy:"

    # Enable/disable cache
    enabled: bool = True


class RedisCache:
    """
    Redis-based caching for the enrollment proxy.

    Provides caching for:
    - GetPolicies responses (per user/group)
    - AD certificate template information
    - EJBCA CA information
    """

    # Key suffixes
    KEY_POLICY = "policy:"
    KEY_TEMPLATE = "template:"
    KEY_CA = "ca:"
    KEY_USER = "user:"

    def __init__(self, config: CacheConfig):
        """
        Initialize Redis cache.

        Args:
            config: Cache configuration
        """
        self.config = config
        self._client: Optional[redis.Redis] = None

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
                decode_responses=True  # Return strings instead of bytes
            )
            self._client = redis.Redis(connection_pool=pool)

            # Test connection
            self._client.ping()
            logger.info(f"Connected to Redis at {self.config.host}:{self.config.port}")

        except redis.RedisError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._client = None

    @property
    def available(self) -> bool:
        """Check if cache is available."""
        if not self.config.enabled or not REDIS_AVAILABLE or not self._client:
            return False
        try:
            self._client.ping()
            return True
        except redis.RedisError:
            return False

    def _make_key(self, prefix: str, *parts) -> str:
        """Create a cache key from parts."""
        key_parts = [self.config.key_prefix, prefix]
        key_parts.extend(str(p) for p in parts)
        return "".join(key_parts)

    def _hash_key(self, data: str) -> str:
        """Create a hash of data for use in keys."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    # Generic operations

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.available:
            return None
        try:
            value = self._client.get(key)
            if value:
                return json.loads(value)
            return None
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL."""
        if not self.available:
            return False
        try:
            ttl = ttl or self.config.default_ttl
            serialized = json.dumps(value, default=str)
            self._client.setex(key, ttl, serialized)
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
        """Delete all keys matching pattern."""
        if not self.available:
            return 0
        try:
            full_pattern = f"{self.config.key_prefix}{pattern}*"
            keys = self._client.keys(full_pattern)
            if keys:
                return self._client.delete(*keys)
            return 0
        except redis.RedisError as e:
            logger.warning(f"Cache clear pattern error for {pattern}: {e}")
            return 0

    # Policy cache operations

    def get_policy_response(self, client_identity: str,
                            groups_hash: str = None) -> Optional[bytes]:
        """
        Get cached GetPolicies response.

        Args:
            client_identity: Client principal name
            groups_hash: Hash of user's group memberships

        Returns:
            Cached SOAP response bytes or None
        """
        cache_key = self._make_key(
            self.KEY_POLICY,
            self._hash_key(client_identity),
            groups_hash or "default"
        )
        result = self.get(cache_key)
        if result:
            # Store as base64 in JSON, decode here
            import base64
            return base64.b64decode(result)
        return None

    def set_policy_response(self, client_identity: str, response: bytes,
                            groups_hash: str = None) -> bool:
        """
        Cache GetPolicies response.

        Args:
            client_identity: Client principal name
            response: SOAP response bytes
            groups_hash: Hash of user's group memberships

        Returns:
            True if cached successfully
        """
        cache_key = self._make_key(
            self.KEY_POLICY,
            self._hash_key(client_identity),
            groups_hash or "default"
        )
        import base64
        return self.set(
            cache_key,
            base64.b64encode(response).decode("ascii"),
            self.config.policy_ttl
        )

    def invalidate_policy_cache(self, client_identity: str = None) -> int:
        """
        Invalidate policy cache.

        Args:
            client_identity: Specific client to invalidate, or None for all

        Returns:
            Number of keys deleted
        """
        if client_identity:
            pattern = f"{self.KEY_POLICY}{self._hash_key(client_identity)}*"
        else:
            pattern = self.KEY_POLICY
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
        return self.clear_pattern(self.KEY_TEMPLATE)

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


def cached(cache: RedisCache, key_func: Callable, ttl: int = None):
    """
    Decorator for caching function results.

    Args:
        cache: RedisCache instance
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
            cache_key = cache._make_key("func:", key_func(*args, **kwargs))

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


class MemoryCache:
    """
    Simple in-memory cache fallback when Redis is not available.

    Uses a dict with TTL tracking. Not suitable for production
    multi-process deployments.
    """

    def __init__(self, config: CacheConfig = None):
        """Initialize memory cache."""
        self.config = config or CacheConfig(enabled=True)
        self._cache: dict = {}
        self._expiry: dict = {}

    @property
    def available(self) -> bool:
        """Always available."""
        return self.config.enabled

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
        return True

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        self._cache.pop(key, None)
        self._expiry.pop(key, None)
        return True

    def clear_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern (simple prefix match)."""
        keys_to_delete = [k for k in self._cache.keys() if k.startswith(pattern)]
        for key in keys_to_delete:
            self.delete(key)
        return len(keys_to_delete)


def create_cache(config: CacheConfig) -> RedisCache:
    """
    Create cache instance based on configuration.

    Falls back to MemoryCache if Redis is not available.
    """
    if config.enabled and REDIS_AVAILABLE:
        cache = RedisCache(config)
        if cache.available:
            return cache
        logger.warning("Redis not available, falling back to memory cache")

    # Return memory cache as fallback
    return MemoryCache(config)
