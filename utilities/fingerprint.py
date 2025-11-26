# utilities/fingerprint.py
# System fingerprinting for GhostGraph C2
# Platform-agnostic collection (OS, hardware, network, BIOS).
# Red team/CTF: Spoof-resistant (serial/CPUID), hashed IDs (FIPS SHA-256), error resilience.
# NIST SP 800-53: IA-5 (device identification), SC-28 (protection of info at rest via hashing).
# Expands original: Adds disk serial (wmic/lsblk), net interfaces, CPUID (asm), BIOS (dmidecode/wmic).

import platform
import uuid
import hashlib
import psutil
import os
import subprocess
import re
import logging

logger = logging.getLogger(__name__)

class SystemFingerprint:
    def __init__(self):
        self.system = platform.system().lower()
        logger.info("Fingerprint initialized", system=self.system)
    
    def _get_disk_serial(self) -> str:
        """Platform-specific disk serial (red team: Unique ID)."""
        try:
            if self.system == 'windows':
                output = subprocess.check_output('wmic diskdrive get SerialNumber', shell=True).decode().strip().split('\n')[1]
            elif self.system == 'linux':
                output = subprocess.check_output('lsblk -no SERIAL /dev/sda', shell=True).decode().strip()
            elif self.system == 'darwin':
                output = subprocess.check_output('system_profiler SPStorageDataType | grep "Serial Number"', shell=True).decode().strip()
            return output or 'unknown'
        except Exception as e:
            logger.warning(f"Disk serial fetch failed: {e}")
            return 'error'
    
    def _get_cpuid(self) -> str:
        """CPUID via asm (CTF: Anti-VM, unique hardware)."""
        try:
            if self.system in ('linux', 'darwin'):
                # x86 asm for CPUID
                cpuid = os.popen('echo "mov $0, %eax; cpuid; echo $ebx $ecx $edx;" | gcc -x assembler -c - -o /dev/stdout | strings').read().strip()
            elif self.system == 'windows':
                cpuid = 'windows_cpuid'  # Use wmic cpu get ProcessorId
                cpuid = subprocess.check_output('wmic cpu get ProcessorId', shell=True).decode().strip().split('\n')[1]
            return cpuid or 'unknown'
        except Exception as e:
            logger.warning(f"CPUID fetch failed: {e}")
            return 'error'
    
    def _get_net_interfaces(self) -> dict:
        """Network interfaces (pen test: Multi-NIC detection)."""
        try:
            return {iface: [addr.address for addr in addrs] for iface, addrs in psutil.net_if_addrs().items()}
        except Exception as e:
            logger.warning(f"Net interfaces failed: {e}")
            return {}
    
    def _get_bios_info(self) -> str:
        """BIOS vendor/version (anti-forensic: VM-specific)."""
        try:
            if self.system == 'windows':
                vendor = subprocess.check_output('wmic bios get Manufacturer', shell=True).decode().strip().split('\n')[1]
            elif self.system == 'linux':
                vendor = subprocess.check_output('dmidecode -s bios-vendor', shell=True).decode().strip()
            elif self.system == 'darwin':
                vendor = 'Apple Inc.'
            return vendor or 'unknown'
        except Exception as e:
            logger.warning(f"BIOS info failed: {e}")
            return 'error'
    
    def collect(self) -> dict:
        """Base fingerprint (original + hashed ID)."""
        try:
            return {
                'os': platform.system(),
                'version': platform.version(),
                'hostname': platform.node(),
                'mac': ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 48, 8)][::-1]),
                'system_id': hashlib.sha256((platform.system() + platform.version() + str(uuid.getnode())).encode()).hexdigest()[:16]
            }
        except Exception as e:
            logger.error(f"Base collect failed: {e}")
            return {'error': str(e)}
    
    def collect_detailed(self) -> dict:
        """Detailed (original + hardware/net/BIOS; FIPS hash ID)."""
        try:
            detailed = {**self.collect(), 'cpu': platform.processor(), 'ram': psutil.virtual_memory().total}
            detailed['disk_serial'] = self._get_disk_serial()
            detailed['cpuid'] = self._get_cpuid()
            detailed['net_interfaces'] = self._get_net_interfaces()
            detailed['bios_vendor'] = self._get_bios_info()
            # FIPS hash all for ID (SP 800-53 IA-5)
            full_str = json.dumps(detailed, sort_keys=True)
            detailed['detailed_id'] = hashlib.sha256(full_str.encode()).hexdigest()
            return detailed
        except Exception as e:
            logger.error(f"Detailed collect failed: {e}")
            return {'error': str(e)}
    
    def get_system_id(self) -> str:
        """Hashed ID (original)."""
        return self.collect().get('system_id', 'unknown')
