# backend/redis_bucket.py
"""
Redis-backed token-bucket helper.

Functions:
- consume_token(key, capacity=5, refill_rate=0.2) -> int
    Returns:
      >=0 : tokens remaining after consume (allowed)
      -1  : not enough tokens (throttle)
       1  : fallback allow when redis unavailable

- redis_health() -> bool
    Quick ping to see if redis is reachable.

Notes:
- Uses a small Lua script for atomic token-bucket logic.
- If Redis is unavailable, this module fails-open (returns 1).
"""
import time
import logging
from typing import Optional

import redis
from redis.exceptions import RedisError

from .config import REDIS_URL

logger = logging.getLogger(__name__)

_redis_client: Optional[redis.Redis] = None
_lua_sha: Optional[str] = None

# Lua script: atomic refill and consume 1 token
_LUA_SCRIPT = """
local k = KEYS[1]
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
-- tokens default to capacity if not set
local tok = tonumber(redis.call('HGET', k, 'tokens') or ARGV[1])
local last = tonumber(redis.call('HGET', k, 'last') or now)
local refill = (now - last) * rate
tok = math.min(cap, tok + refill)
if tok >= 1 then
    tok = tok - 1
    redis.call('HSET', k, 'tokens', tostring(tok))
    redis.call('HSET', k, 'last', tostring(now))
    redis.call('EXPIRE', k, 3600)
    return tok
else
    redis.call('HSET', k, 'tokens', tostring(tok))
    redis.call('HSET', k, 'last', tostring(now))
    redis.call('EXPIRE', k, 3600)
    return -1
end
"""


def _get_redis() -> Optional[redis.Redis]:
    """
    Lazily create and return a redis.Redis client from REDIS_URL.
    Returns None when redis could not be initialized.
    """
    global _redis_client, _lua_sha
    if _redis_client is not None:
        return _redis_client

    if not REDIS_URL:
        logger.info("REDIS_URL not configured; redis disabled.")
        return None

    try:
        # Create client with sensible timeouts
        _redis_client = redis.from_url(
            REDIS_URL,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
            decode_responses=True,
        )
        # test ping
        _redis_client.ping()
        # register script (cache sha)
        try:
            _lua_sha = _redis_client.script_load(_LUA_SCRIPT)
        except Exception:
            _lua_sha = None
        logger.info("Connected to Redis at %s", REDIS_URL)
        return _redis_client
    except Exception as e:
        logger.exception("Failed to initialize Redis client: %s", e)
        _redis_client = None
        _lua_sha = None
        return None


def redis_health() -> bool:
    """Return True if redis is reachable/pingable, False otherwise."""
    r = _get_redis()
    if r is None:
        return False
    try:
        return bool(r.ping())
    except Exception:
        return False


def consume_token(key: str, capacity: int = 5, refill_rate: float = 0.2) -> int:
    """
    Atomically consume one token from the bucket stored at `key`.

    Parameters:
      - key: identifier (usually src_ip or session id). It will be prefixed with 'tb:' internally.
      - capacity: maximum tokens allowed in bucket (burst capacity).
      - refill_rate: tokens per second refill rate (float).

    Returns:
      - >=0 : tokens remaining after consume (allowed)
      - -1  : not enough tokens (throttle)
      - 1   : fallback allow when redis unavailable
    """
    r = _get_redis()
    now = time.time()
    if r is None:
        # fail-open: allow when redis unavailable
        return 1

    # sanitize key a bit
    k = f"tb:{str(key)}"

    try:
        # Prefer evalsha for caching if sha is available
        if _lua_sha:
            res = r.evalsha(_lua_sha, 1, k, str(int(capacity)), str(float(refill_rate)), str(now))
        else:
            res = r.eval(_LUA_SCRIPT, 1, k, str(int(capacity)), str(float(refill_rate)), str(now))

        # Normalize result to int
        try:
            return int(float(res))
        except Exception:
            # if something odd returned, fallback to allow
            logger.warning("Unexpected Lua result for token-bucket: %r", res)
            return 1
    except RedisError:
        # Redis errors -> log and fail-open
        logger.exception("Redis token-bucket error for key %s", k)
        return 1
    except Exception:
        logger.exception("Unexpected error in consume_token for key %s", k)
        return 1
