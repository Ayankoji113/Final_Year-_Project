"""Layer 1 (rate half) - Redis sliding-window counters with real enforcement.

The previous gateway computed a window count and passed it to the model as a
feature, but never enforced anything - so "rate limiting" existed only as a
number. Here the limit is an actual control, and the same counters double as
behavioural features for the ML layers.

Three signals per client, one Redis round trip (pipelined):
  window  - requests in the last RATE_WINDOW_SECS   -> sustained abuse
  burst   - requests in the last RATE_BURST_SECS    -> spikes a long window hides
  spread  - distinct endpoint templates touched     -> scanning / enumeration
"""
import time
from dataclasses import dataclass
from typing import Optional

from common import config


@dataclass
class RateState:
    window_count: int = 0
    burst_count: int = 0
    distinct_paths: int = 0
    limited: bool = False
    reason: str = ""
    degraded: bool = False   # Redis unavailable; counts are not trustworthy


class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client

    async def check(self, client_id: str, template: str) -> RateState:
        """Record this request and return the client's current rate state."""
        if self.redis is None:
            return RateState(degraded=True)

        now = time.time()
        wkey = f"rl:w:{client_id}"
        bkey = f"rl:b:{client_id}"
        pkey = f"rl:p:{client_id}"
        # Unique member per request: a bare timestamp collides under concurrency
        # and silently under-counts exactly when load is highest.
        member = f"{now:.6f}:{id(self):x}:{time.perf_counter_ns()}"

        try:
            pipe = self.redis.pipeline()
            pipe.zadd(wkey, {member: now})
            pipe.zremrangebyscore(wkey, 0, now - config.RATE_WINDOW_SECS)
            pipe.zcard(wkey)
            pipe.expire(wkey, config.RATE_WINDOW_SECS * 2)

            pipe.zadd(bkey, {member: now})
            pipe.zremrangebyscore(bkey, 0, now - config.RATE_BURST_SECS)
            pipe.zcard(bkey)
            pipe.expire(bkey, config.RATE_BURST_SECS * 4)

            # HyperLogLog: O(1) memory regardless of how many endpoints a
            # scanner touches, which is the whole point of the signal.
            pipe.pfadd(pkey, template)
            pipe.pfcount(pkey)
            pipe.expire(pkey, config.RATE_WINDOW_SECS * 2)

            res = await pipe.execute()
            window_count = int(res[2])
            burst_count = int(res[6])
            distinct = int(res[9])
        except Exception:
            # Never let a Redis outage take the gateway down. We lose the rate
            # signal (features degrade to zero) but requests keep flowing and
            # the signature + model layers still apply.
            return RateState(degraded=True)

        st = RateState(window_count=window_count, burst_count=burst_count,
                       distinct_paths=distinct)

        if burst_count > config.RATE_BURST_LIMIT:
            st.limited = True
            st.reason = (f"burst limit exceeded: {burst_count} requests in "
                         f"{config.RATE_BURST_SECS}s (limit {config.RATE_BURST_LIMIT})")
        elif window_count > config.RATE_LIMIT:
            st.limited = True
            st.reason = (f"rate limit exceeded: {window_count} requests in "
                         f"{config.RATE_WINDOW_SECS}s (limit {config.RATE_LIMIT})")
        return st

    async def reset(self, client_id: Optional[str] = None):
        """Test/ops helper: clear counters for one client or all of them."""
        if self.redis is None:
            return
        if client_id:
            await self.redis.delete(f"rl:w:{client_id}", f"rl:b:{client_id}",
                                    f"rl:p:{client_id}")
        else:
            keys = [k async for k in self.redis.scan_iter(match="rl:*", count=500)]
            if keys:
                await self.redis.delete(*keys)
