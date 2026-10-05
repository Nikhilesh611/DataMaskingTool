"""Real-Time Pub/Sub Invalidation Mesh (Phase 4).

Architecture
------------
When enterprise administrators update a masking policy or group mapping via the
Control Plane, worker nodes across the cluster must invalidate their local L1
and JWKS caches in real-time without restarting or waiting for TTL expiry.

Pub/Sub Protocol
----------------
Channel: ``masking:cache:invalidation``
Payload: JSON string
  {
    "action": "invalidate_tenant",
    "tenant_id": "<uuid>",
    "timestamp": 1727800000.123
  }

Lifecycle
---------
Started during FastAPI lifespan startup as an asyncio task when Redis is connected;
cleanly cancelled and drained during shutdown.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from app.cache.l1_cache import get_l1_cache
from app.cache.redis_client import RedisManager, get_redis_manager
from app.idp.jwks_client import get_jwks_cache
from app.logging_config import get_app_logger

INVALIDATION_CHANNEL = "masking:cache:invalidation"


class PubSubMesh:
    """Manages real-time cache invalidation broadcasts and subscriptions."""

    def __init__(self, redis_manager: RedisManager) -> None:
        self._redis_mgr = redis_manager
        self._listener_task: Optional[asyncio.Task] = None
        self._running = False

    async def broadcast_invalidation(
        self,
        tenant_id: str,
        action: str = "invalidate_tenant",
    ) -> None:
        """Broadcast invalidation event and evict local cache immediately.

        Guarantees local node eviction even if Redis is unreachable.
        """
        logger = get_app_logger()

        # 1. Evict local caches synchronously
        l1 = get_l1_cache()
        l1_evicted = l1.invalidate_tenant(tenant_id)

        jwks = get_jwks_cache()
        jwks.invalidate_tenant(tenant_id)

        logger.info(
            "Local caches evicted for tenant '%s' (L1 keys: %d)",
            tenant_id,
            l1_evicted,
        )

        # 2. Publish to Redis mesh if connected
        if self._redis_mgr.is_connected:
            payload = json.dumps(
                {
                    "action": action,
                    "tenant_id": tenant_id,
                    "timestamp": time.time(),
                }
            )
            try:
                recipients = await self._redis_mgr.publish(INVALIDATION_CHANNEL, payload)
                logger.info(
                    "Broadcasted invalidation for tenant '%s' to %d subscribers",
                    tenant_id,
                    recipients,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to broadcast invalidation for tenant '%s': %s",
                    tenant_id,
                    exc,
                )

    async def _listener_loop(self) -> None:
        """Background coroutine listening for invalidation events from peer nodes."""
        logger = get_app_logger()
        client = self._redis_mgr.get_raw_client()
        if client is None:
            return

        try:
            pubsub = client.pubsub()
            await pubsub.subscribe(INVALIDATION_CHANNEL)
            logger.info("Subscribed to cache invalidation channel '%s'", INVALIDATION_CHANNEL)

            while self._running:
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if message and message.get("type") == "message":
                        data_str = message.get("data")
                        if isinstance(data_str, str):
                            event = json.loads(data_str)
                            tenant_id = event.get("tenant_id")
                            if tenant_id:
                                get_l1_cache().invalidate_tenant(tenant_id)
                                get_jwks_cache().invalidate_tenant(tenant_id)
                                logger.info(
                                    "Received pub/sub invalidation for tenant '%s'",
                                    tenant_id,
                                )
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("Error in invalidation listener loop: %s", exc)
                    await asyncio.sleep(1.0)

            await pubsub.unsubscribe(INVALIDATION_CHANNEL)
            await pubsub.close()
        except Exception as exc:
            logger.warning("PubSub invalidation listener stopped: %s", exc)

    def start_listener(self) -> None:
        """Start background listener task if Redis is available."""
        if not self._redis_mgr.is_connected or self._running:
            return
        self._running = True
        self._listener_task = asyncio.create_task(self._listener_loop())

    async def stop_listener(self) -> None:
        """Stop background listener and wait for task termination."""
        self._running = False
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None


# ── Global Singleton ──────────────────────────────────────────────────────────

_pubsub_mesh: Optional[PubSubMesh] = None


def get_pubsub_mesh() -> PubSubMesh:
    global _pubsub_mesh
    if _pubsub_mesh is None:
        _pubsub_mesh = PubSubMesh(get_redis_manager())
    return _pubsub_mesh


def set_pubsub_mesh(mesh: PubSubMesh) -> None:
    global _pubsub_mesh
    _pubsub_mesh = mesh
