# utilities/cleanup.py
# Cleanup for GhostGraph C2
# Secure delete (DoD 5220.22-M 3-pass overwrite + unlink), dir shred, memory zero (sodium sim).
# Red team/CTF: Anti-forensic (zero timestamps, random names), error resilience, audit.
# NIST SP 800-53: MP-6 (media sanitization), SC-28 (info protection at rest), FIPS 140-3 IG 7.11 (zeroization).

import os
import shutil
import logging
import secrets  # FIPS CSPRNG
import structlog  # Structured logs

logger = structlog.get_logger()

def secure_delete(file_path: str, passes: int = 3) -> bool:
    """DoD 5220.22-M secure delete: Multi-pass overwrite (random/zero/complement), unlink.
    FIPS 140-3 IG 7.11: Zeroization equivalent for files."""
    try:
        if not os.path.exists(file_path):
            logger.warning(f"File not found for delete: {file_path}")
            return False
        
        size = os.path.getsize(file_path)
        with open(file_path, 'ba+') as f:
            for _ in range(passes):
                f.seek(0)
                # Pass 1: Random (CSPRNG)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
                # Pass 2: Complement (invert)
                f.seek(0)
                data = f.read()
                f.seek(0)
                f.write(bytes(~b & 0xFF for b in data))
                f.flush()
                os.fsync(f.fileno())
                # Pass 3: Zero
                f.seek(0)
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
        
        # Random rename (anti-recovery)
        rand_name = secrets.token_hex(16)
        os.rename(file_path, os.path.join(os.path.dirname(file_path), rand_name))
        
        # Unlink + zero metadata (timestamps)
        os.utime(rand_name, (0, 0))
        os.remove(rand_name)
        
        logger.info("Secure delete completed", path=file_path, passes=passes)
        return True
    except Exception as e:
        logger.error(f"Secure delete failed: {e}", path=file_path)
        return False

def cleanup_logs(logs: list = None):
    """Original + expanded: Secure delete logs, dirs (rmtree with shred)."""
    if logs is None:
        logs = ['/tmp/ghostgraph.log', os.path.expanduser('~/.ghostgraph'), '/tmp/ghostgraph_jobs.json']
    
    for log in logs:
        if os.path.isfile(log):
            secure_delete(log)
        elif os.path.isdir(log):
            for root, dirs, files in os.walk(log, topdown=False):
                for file in files:
                    secure_delete(os.path.join(root, file))
            shutil.rmtree(log, ignore_errors=True)
    
    # Memory zero sim (Python GC limits; advise sodium.mlock/zero for keys)
    # For keys: import gc; gc.collect()

def cleanup_dead_letter(dl_queue: asyncio.Queue):
    """New: Securely clear dead letter queue (red team: No traces)."""
    while not dl_queue.empty():
        item = dl_queue.get_nowait()
        # Zero sensitive (sim)
        item = {}
    logger.info("Dead letter queue cleaned")

# Call in implant/server cleanup; e.g., cleanup_logs(); cleanup_dead_letter(handler.dead_letter_queue)
