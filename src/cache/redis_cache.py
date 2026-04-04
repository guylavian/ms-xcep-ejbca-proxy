"""
Redis caching layer for certificate enrollment proxy.

Caches GetPolicies responses and other expensive operations
to reduce load on LDAP and EJBCA backends.

Features:
- Redis + in-memory fallback with identical interface
- Safe key building with delimiter
- Compression for large policy responses
- SCAN-based pattern invalidation (no KEYS)
- Cached availability checks (avoid ping per operation)
- Stampede protection with tokenized distributed locks (safe unlock via Lua)
- Proper JSON serialize/deserialize for datetime + bytes
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import time
import uuid
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional, Protocol, runtime_checkable

try:
    import redis  # type: ignore

    REDIS_AVAILABLE = True
except ImportError:
    redis = None  # type: ignore
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class CacheError(Exception):
    """Cache operation error."""


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
    policy_ttl: int = 7200  # 2 hours for GetPolicies responses
    template_ttl: int = 14400  # 4 hours for AD template info
    ca_info_ttl: int = 86400  # 24 hours for CA information

    # Key prefix (namespace)
    key_prefix: str = "xcep_proxy"

    # Enable/disable cache entirely
    enabled: bool = True

    # Compression threshold (bytes): compress responses larger than this
    compression_threshold: int = 1024

    # Availability check interval (seconds): don't ping Redis on every call
    availability_check_interval: float = 5.0

    # Stampede protection lock TTL (seconds)
    lock_ttl: int = 10


# Key delimiter - prevents collisions
KEY_DELIMITER = ":"


@runtime_checkable
class CacheBackend(Protocol):
    """Interface for cache backends (Redis and Memory)."""

    config: CacheConfig

    @property
    def available(self) -> bool:
        ...

    def make_key(self, *parts: Any) -> str:
        ...

    def get(self, key: str) -> Optional[Any]:
        ...

    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        ...

    def delete(self, key: str) -> bool:
        ...

    def clear_pattern(self, pattern: str) -> int:
        ...

    # High-level ops used by enrollment proxy
    def get_policy_response(self, client_identity: str, groups_hash: str | None = None) -> Optional[bytes]:
        ...

    def set_policy_response(self, client_identity: str, response: bytes, groups_hash: str | None = None) -> bool:
        ...

    def invalidate_policy_cache(self, client_identity: str | None = None) -> int:
        ...

    # Optional but implemented by both backends here
    def acquire_lock(self, lock_name: str, ttl: int | None = None) -> Optional[str]:
        ...

    def release_lock(self, lock_name: str, token: str) -> bool:
        ...


class BaseCacheBackend(ABC):
    """
    Abstract base class for cache backends.

    Provides:
    - Consistent key generation
    - Compression helpers
    - JSON serialize/deserialize with datetime/bytes support
    - High-level cache operations (policy/templates/CA/user groups)
    """

    # Key type prefixes
    KEY_POLICY = "policy"
    KEY_TEMPLATE = "template"
    KEY_CA = "ca"
    KEY_USER = "user"
    KEY_LOCK = "lock"

    def __init__(self, config: CacheConfig):
        self.config = config

    # ---- Key helpers ----

    def make_key(self, *parts: Any) -> str:
        """
        Create a cache key from parts with consistent delimiter.
        Example: xcep_proxy:policy:abc123:default
        """
        all_parts = [self.config.key_prefix]
        all_parts.extend(str(p) for p in parts if p is not None and str(p) != "")
        return KEY_DELIMITER.join(all_parts)

    # Backward-compatible alias (avoid breaking existing code)
    def _make_key(self, *parts: Any) -> str:
        return self.make_key(*parts)

    def _hash_key(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]

    # ---- Compression helpers (bytes) ----

    def _compress(self, data: bytes) -> bytes:
        """
        Compress data if above threshold and compression is beneficial.
        Prefix with b'Z' for compressed and b'R' for raw.
        """
        if len(data) > self.config.compression_threshold:
            compressed = zlib.compress(data, level=6)
            if len(compressed) < len(data):
                return b"Z" + compressed
        return b"R" + data

    def _decompress(self, data: bytes) -> bytes:
        """Decompress data if prefixed, otherwise return as-is (legacy)."""
        if not data:
            return data
        prefix = data[:1]
        payload = data[1:]
        if prefix == b"Z":
            return zlib.decompress(payload)
        if prefix == b"R":
            return payload
        return data  # legacy without prefix

    # ---- JSON serialize/deserialize ----

    def _serialize(self, value: Any) -> str:
        return json.dumps(value, default=self._json_serializer)

    def _deserialize(self, data: str) -> Any:
        return json.loads(data, object_hook=self._json_object_hook)

    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return {"__datetime__": obj.isoformat()}
        if isinstance(obj, bytes):
            import base64
            return {"__bytes__": base64.b64encode(obj).decode("ascii")}
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    @staticmethod
    def _json_object_hook(obj: dict) -> Any:
        if "__datetime__" in obj:
            return datetime.fromisoformat(obj["__datetime__"])
        if "__bytes__" in obj:
            import base64
            return base64.b64decode(obj["__bytes__"].encode("ascii"))
        return obj

    # ---- Abstract low-level methods ----

    @property
    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        ...

    @abstractmethod
    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        ...

    @abstractmethod
    def clear_pattern(self, pattern: str) -> int:
        ...

    @abstractmethod
    def _get_raw(self, key: str) -> Optional[bytes]:
        ...

    @abstractmethod
    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        ...

    # ---- High-level operations ----

    # Policy
    def get_policy_response(self, client_identity: str, groups_hash: str | None = None) -> Optional[bytes]:
        cache_key = self.make_key(self.KEY_POLICY, self._hash_key(client_identity), groups_hash or "default")
        raw = self._get_raw(cache_key)
        if raw:
            try:
                return self._decompress(raw)
            except Exception as e:
                logger.warning(f"Policy decompress failed for {cache_key}: {e}")
        return None

    def set_policy_response(self, client_identity: str, response: bytes, groups_hash: str | None = None) -> bool:
        cache_key = self.make_key(self.KEY_POLICY, self._hash_key(client_identity), groups_hash or "default")
        return self._set_raw(cache_key, self._compress(response), self.config.policy_ttl)

    def invalidate_policy_cache(self, client_identity: str | None = None) -> int:
        if client_identity:
            pattern = self.make_key(self.KEY_POLICY, self._hash_key(client_identity), "*")
        else:
            pattern = self.make_key(self.KEY_POLICY, "*")
        return self.clear_pattern(pattern)

    # Templates
    def get_templates(self) -> Optional[list]:
        return self.get(self.make_key(self.KEY_TEMPLATE, "all"))

    def set_templates(self, templates: list) -> bool:
        return self.set(self.make_key(self.KEY_TEMPLATE, "all"), templates, self.config.template_ttl)

    def get_template(self, template_name: str) -> Optional[dict]:
        return self.get(self.make_key(self.KEY_TEMPLATE, template_name.lower()))

    def set_template(self, template_name: str, template: dict) -> bool:
        return self.set(self.make_key(self.KEY_TEMPLATE, template_name.lower()), template, self.config.template_ttl)

    def invalidate_templates(self) -> int:
        return self.clear_pattern(self.make_key(self.KEY_TEMPLATE, "*"))

    # CA info
    def get_ca_info(self, ca_name: str) -> Optional[dict]:
        return self.get(self.make_key(self.KEY_CA, ca_name.lower()))

    def set_ca_info(self, ca_name: str, ca_info: dict) -> bool:
        return self.set(self.make_key(self.KEY_CA, ca_name.lower()), ca_info, self.config.ca_info_ttl)

    def get_ca_list(self) -> Optional[list]:
        return self.get(self.make_key(self.KEY_CA, "list"))

    def set_ca_list(self, cas: list) -> bool:
        return self.set(self.make_key(self.KEY_CA, "list"), cas, self.config.ca_info_ttl)

    # User groups
    def get_user_groups(self, principal: str) -> Optional[list]:
        return self.get(self.make_key(self.KEY_USER, self._hash_key(principal), "groups"))

    def set_user_groups(self, principal: str, groups: list, ttl: int = 1800) -> bool:
        return self.set(self.make_key(self.KEY_USER, self._hash_key(principal), "groups"), groups, ttl)

    # Locks (default behavior; overridden where needed)
    def acquire_lock(self, lock_name: str, ttl: int | None = None) -> Optional[str]:
        # Default: no-op lock, always "acquired"
        return "no-lock"

    def release_lock(self, lock_name: str, token: str) -> bool:
        return True


class RedisCache(BaseCacheBackend):
    """
    Redis cache backend with:
    - Connection pooling
    - SCAN invalidation
    - Availability caching
    - Safe distributed locks (token + Lua unlock)
    """

    _UNLOCK_LUA = """
    if redis.call("GET", KEYS[1]) == ARGV[1] then
        return redis.call("DEL", KEYS[1])
    else
        return 0
    end
    """

    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self._client: Optional["redis.Redis"] = None
        self._last_available_check: float = 0.0
        self._last_available_result: bool = False
        if config.enabled and REDIS_AVAILABLE:
            self._connect()

    def _connect(self) -> None:
        try:
            pool = redis.ConnectionPool(  # type: ignore[attr-defined]
                host=self.config.host,
                port=self.config.port,
                db=self.config.db,
                password=self.config.password,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                decode_responses=False,  # we handle encoding
            )
            self._client = redis.Redis(connection_pool=pool)  # type: ignore[attr-defined]
            self._client.ping()
            self._last_available_result = True
            self._last_available_check = time.time()
            logger.info(f"Connected to Redis at {self.config.host}:{self.config.port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._client = None
            self._last_available_result = False

    @property
    def available(self) -> bool:
        if not self.config.enabled or not REDIS_AVAILABLE or not self._client:
            return False

        now = time.time()
        if now - self._last_available_check < self.config.availability_check_interval:
            return self._last_available_result

        try:
            self._client.ping()
            self._last_available_result = True
        except Exception:
            self._last_available_result = False

        self._last_available_check = now
        return self._last_available_result

    def get(self, key: str) -> Optional[Any]:
        if not self.available:
            return None
        try:
            value = self._client.get(key)  # type: ignore[union-attr]
            if not value:
                return None
            return self._deserialize(value.decode("utf-8"))
        except Exception as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        if not self.available:
            return False
        try:
            ttl = ttl or self.config.default_ttl
            serialized = self._serialize(value).encode("utf-8")
            self._client.setex(key, ttl, serialized)  # type: ignore[union-attr]
            return True
        except Exception as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        if not self.available:
            return False
        try:
            self._client.delete(key)  # type: ignore[union-attr]
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for {key}: {e}")
            return False

    def clear_pattern(self, pattern: str) -> int:
        """
        Delete keys matching pattern using SCAN.
        Pattern should be glob-style (use '*').
        """
        if not self.available:
            return 0

        count = 0
        batch: list[bytes] = []
        batch_size = 200

        try:
            # scan_iter returns bytes keys because decode_responses=False
            for k in self._client.scan_iter(match=pattern, count=500):  # type: ignore[union-attr]
                batch.append(k)
                if len(batch) >= batch_size:
                    self._client.delete(*batch)  # type: ignore[union-attr]
                    count += len(batch)
                    batch = []

            if batch:
                self._client.delete(*batch)  # type: ignore[union-attr]
                count += len(batch)

            return count
        except Exception as e:
            logger.warning(f"Cache clear_pattern error for {pattern}: {e}")
            return 0

    def _get_raw(self, key: str) -> Optional[bytes]:
        if not self.available:
            return None
        try:
            return self._client.get(key)  # type: ignore[union-attr]
        except Exception as e:
            logger.warning(f"Cache get_raw error for {key}: {e}")
            return None

    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        if not self.available:
            return False
        try:
            self._client.setex(key, ttl, value)  # type: ignore[union-attr]
            return True
        except Exception as e:
            logger.warning(f"Cache set_raw error for {key}: {e}")
            return False

    def acquire_lock(self, lock_name: str, ttl: int | None = None) -> Optional[str]:
        """
        Acquire distributed lock. Returns token if acquired, None if not.
        """
        if not self.available:
            return "no-cache"  # treat as acquired

        ttl = ttl or self.config.lock_ttl
        key = self.make_key(self.KEY_LOCK, lock_name)
        token = uuid.uuid4().hex
        try:
            ok = self._client.set(key, token.encode("ascii"), nx=True, ex=ttl)  # type: ignore[union-attr]
            return token if ok else None
        except Exception:
            return "no-cache"

    def release_lock(self, lock_name: str, token: str) -> bool:
        """
        Release lock only if token matches (prevents deleting someone else's lock).
        """
        if not self.available:
            return True
        key = self.make_key(self.KEY_LOCK, lock_name)
        try:
            res = self._client.eval(self._UNLOCK_LUA, 1, key, token.encode("ascii"))  # type: ignore[union-attr]
            return bool(res)
        except Exception:
            return True


class MemoryCache(BaseCacheBackend):
    """
    In-memory cache fallback. Not suitable for multi-process production.

    Implements same behavior as RedisCache for compatibility.
    """

    def __init__(self, config: CacheConfig | None = None):
        super().__init__(config or CacheConfig(enabled=True))
        self._cache: dict[str, Any] = {}
        self._expiry: dict[str, datetime] = {}
        self._raw_cache: dict[str, bytes] = {}
        self._raw_expiry: dict[str, datetime] = {}

    @property
    def available(self) -> bool:
        return bool(self.config.enabled)

    def _cleanup_expired(self) -> None:
        now = datetime.now()
        expired_keys = [k for k, exp in self._expiry.items() if now > exp]
        for k in expired_keys:
            self._cache.pop(k, None)
            self._expiry.pop(k, None)

        expired_raw = [k for k, exp in self._raw_expiry.items() if now > exp]
        for k in expired_raw:
            self._raw_cache.pop(k, None)
            self._raw_expiry.pop(k, None)

    def get(self, key: str) -> Optional[Any]:
        if not self.available:
            return None
        exp = self._expiry.get(key)
        if exp and datetime.now() > exp:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)
            return None
        return self._cache.get(key)

    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        if not self.available:
            return False
        ttl = ttl or self.config.default_ttl
        self._cache[key] = value
        self._expiry[key] = datetime.now() + timedelta(seconds=ttl)

        # periodic cleanup
        if len(self._cache) % 200 == 0:
            self._cleanup_expired()

        return True

    def delete(self, key: str) -> bool:
        self._cache.pop(key, None)
        self._expiry.pop(key, None)
        self._raw_cache.pop(key, None)
        self._raw_expiry.pop(key, None)
        return True

    def clear_pattern(self, pattern: str) -> int:
        """
        Glob-style pattern (supports '*').
        """
        count = 0
        keys = [k for k in self._cache.keys() if fnmatch.fnmatch(k, pattern)]
        for k in keys:
            self._cache.pop(k, None)
            self._expiry.pop(k, None)
            count += 1

        raw_keys = [k for k in self._raw_cache.keys() if fnmatch.fnmatch(k, pattern)]
        for k in raw_keys:
            self._raw_cache.pop(k, None)
            self._raw_expiry.pop(k, None)
            count += 1

        return count

    def _get_raw(self, key: str) -> Optional[bytes]:
        if not self.available:
            return None
        exp = self._raw_expiry.get(key)
        if exp and datetime.now() > exp:
            self._raw_cache.pop(key, None)
            self._raw_expiry.pop(key, None)
            return None
        return self._raw_cache.get(key)

    def _set_raw(self, key: str, value: bytes, ttl: int) -> bool:
        if not self.available:
            return False
        self._raw_cache[key] = value
        self._raw_expiry[key] = datetime.now() + timedelta(seconds=ttl)
        return True

    def acquire_lock(self, lock_name: str, ttl: int | None = None) -> Optional[str]:
        # single-process fallback: always "acquired"
        return "mem"

    def release_lock(self, lock_name: str, token: str) -> bool:
        return True


def create_cache(config: CacheConfig) -> BaseCacheBackend:
    """
    Create cache instance based on configuration.
    Returns RedisCache if possible, otherwise MemoryCache.
    """
    if config.enabled and REDIS_AVAILABLE:
        cache = RedisCache(config)
        if cache.available:
            return cache
        logger.warning("Redis not available, falling back to memory cache")
    return MemoryCache(config)


def cached(cache: CacheBackend, key_func: Callable[..., str], ttl: int | None = None):
    """
    Decorator for caching function results (no stampede protection).
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not cache.available:
                return func(*args, **kwargs)

            suffix = key_func(*args, **kwargs)
            cache_key = cache.make_key("func", suffix)

            result = cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return result

            result = func(*args, **kwargs)
            if result is not None:
                cache.set(cache_key, result, ttl or cache.config.default_ttl)
            return result

        return wrapper

    return decorator


def cached_with_lock(
        cache: CacheBackend,
        key_func: Callable[..., str],
        ttl: int | None = None,
        lock_ttl: int | None = None,
        wait_timeout: float = 2.0,
        wait_step: float = 0.1,
):
    """
    Decorator for caching with stampede protection.

    - If key is missing, attempt to acquire a lock.
    - If lock is held, wait (poll cache) up to wait_timeout.
    - If still missing after waiting, compute as fallback.

    Lock release is safe (token-based) for Redis.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not cache.available:
                return func(*args, **kwargs)

            suffix = key_func(*args, **kwargs)
            cache_key = cache.make_key("func", suffix)
            lock_name = f"func:{suffix}"

            # Fast path
            result = cache.get(cache_key)
            if result is not None:
                return result

            # Acquire lock
            effective_lock_ttl = lock_ttl or cache.config.lock_ttl
            token = cache.acquire_lock(lock_name, effective_lock_ttl)

            if token is None:
                # Someone else is computing; wait for cache to fill
                deadline = time.time() + wait_timeout
                while time.time() < deadline:
                    time.sleep(wait_step)
                    result = cache.get(cache_key)
                    if result is not None:
                        return result
                # Timeout fallback
                return func(*args, **kwargs)

            try:
                # Double-check after acquiring lock (race)
                result = cache.get(cache_key)
                if result is not None:
                    return result

                result = func(*args, **kwargs)
                if result is not None:
                    cache.set(cache_key, result, ttl or cache.config.default_ttl)
                return result
            finally:
                # Only release if we truly own a token lock
                if token not in ("no-cache", "no-lock", "mem"):
                    cache.release_lock(lock_name, token)

        return wrapper

    return decorator
