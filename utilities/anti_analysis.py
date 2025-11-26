# utilities/anti_analysis.py
# Anti-analysis for GhostGraph C2
# VM/debug/sandbox detection (timing, files, registry, hooks, memory).
# Red team/CTF: Multi-layer evasion (ptrace, process scans, VM artifacts, ld_preload, FIPS random delays).
# NIST SP 800-53: SC-30 (concealment), SI-4 (monitoring for intrusion), expanded original with Windows/Mac checks.

import os
import time
import platform
import psutil
import subprocess
import re
import logging
import random

logger = logging.getLogger(__name__)

class AntiAnalysis:
    def __init__(self):
        self.system = platform.system().lower()
        logger.info("AntiAnalysis initialized", system=self.system)
    
    def _random_delay(self) -> float:
        """FIPS-compliant random delay (os.urandom for CSPRNG/SP 800-90A)."""
        return random.uniform(0.01, 0.1) + (int.from_bytes(os.urandom(1)) / 255.0)
    
    def detect_debugger(self) -> bool:
        """Original + advanced (ld_preload hooks, GDB strs, Windows IsDebuggerPresent)."""
        try:
            if self.system == 'linux':
                with open('/proc/self/status') as f:
                    if 'TracerPid:\t0' not in f.read():
                        return True
                # LD_PRELOAD hook check
                if 'LD_PRELOAD' in os.environ or os.path.exists('/proc/self/environ') and b'LD_PRELOAD' in open('/proc/self/environ', 'rb').read():
                    return True
            elif self.system == 'windows':
                import ctypes
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    return True
                # Anti-GDB/IDA strings in memory (red team evasion)
                proc = psutil.Process(os.getpid())
                if any('gdb' in m.path.lower() or 'ida' in m.path.lower() for m in proc.memory_maps()):
                    return True
            elif self.system == 'darwin':
                # Mac ptrace deny check
                import ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library('c'))
                if libc.ptrace(31, 0, 0, 0) == -1:  # PT_DENY_ATTACH
                    return True
            
            suspicious_procs = ['wireshark', 'tcpdump', 'procmon', 'ollydbg', 'ida', 'gdb', 'lldb', 'xcode']
            for proc in psutil.process_iter(['name']):
                if any(s in proc.info['name'].lower() for s in suspicious_procs):
                    return True
            return False
        except Exception as e:
            logger.warning(f"Debugger detect failed: {e}")
            return False
    
    def detect_virtualization(self) -> bool:
        """Original + expanded (VM files/registry, hypervisor flags, Mac Parallels)."""
        try:
            indicators = [
                '/.dockerenv', '/proc/xen', '/proc/vz', '/sys/hypervisor/type',  # Container/VM
                'vmware', 'virtualbox', 'qemu', 'xen', 'kvm', 'hyper-v', 'parallels'
            ]
            if any(os.path.exists(i) for i in indicators if os.path.isabs(i)):
                return True
            
            if self.system == 'linux':
                cpuinfo = open('/proc/cpuinfo', 'r').read().lower()
                if 'hypervisor' in cpuinfo or 'vmx' in cpuinfo or 'svm' in cpuinfo:
                    return True
                dmesg = subprocess.check_output('dmesg | grep -i hypervisor', shell=True).decode().lower()
                if 'detected' in dmesg:
                    return True
            elif self.system == 'windows':
                import winreg
                reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Services\Disk\Enum")
                if 'vmware' in winreg.EnumValue(key, 0)[1].lower():
                    return True
                # Hyper-V check
                if subprocess.check_output('systeminfo', shell=True).decode().lower().count('hyper-v') > 0:
                    return True
            elif self.system == 'darwin':
                if 'parallels' in subprocess.check_output('system_profiler SPHardwareDataType', shell=True).decode().lower():
                    return True
            
            # Original check
            if 'virtual' in platform.release().lower():
                return True
            return False
        except Exception as e:
            logger.warning(f"VM detect failed: {e}")
            return False
    
    def detect_sandbox(self) -> bool:
        """New: Sandbox checks (low file count, recent boot, low RAM, no user files)."""
        try:
            # Low disk files (CTF sandboxes)
            if len(os.listdir('/')) < 20:  # Arbitrary low
                return True
            # Recent boot (uptime < 5min)
            if psutil.boot_time() > time.time() - 300:
                return True
            # Low RAM usage (sandbox idle)
            if psutil.virtual_memory().used < 100 * 1024 * 1024:  # <100MB
                return True
            # No user docs (red team: Real systems have files)
            user_dir = os.path.expanduser('~')
            if len(os.listdir(user_dir)) < 5:
                return True
            return False
        except Exception as e:
            logger.warning(f"Sandbox detect failed: {e}")
            return False
    
    def should_continue(self) -> bool:
        """Original timing + delays (FIPS random/SP 800-90A), combined checks."""
        try:
            start = time.time()
            # Complex compute for timing (anti-debug slowdown)
            _ = sum(i**2 for i in range(100000))
            elapsed = time.time() - start
            if elapsed > 0.1:  # Threshold hardened
                return False
            # Random delays (CSPRNG)
            time.sleep(self._random_delay())
            # Combined detections (SP 800-53 SI-4: Multi-indicator)
            if self.detect_debugger() or self.detect_virtualization() or self.detect_sandbox():
                return False
            return True
        except Exception as e:
            logger.error(f"Should continue failed: {e}")
            return False  # Fail-safe

    def _random_delay(self) -> float:
        """FIPS-compliant random delay (os.urandom CSPRNG/SP 800-90A)."""
        rand_byte = os.urandom(1)[0] / 255.0  # Uniform [0,1]
        return 0.01 + rand_byte * 0.09  # 0.01-0.1s
