import time
import random
from core.channels import BaseChannel

class TimingAdvancedChannel(BaseChannel):
    def __init__(self, config: dict):
        super().__init__(config)
        self.base_delay = config.get('base_delay', 0.1)  # Per bit
        self.jitter_range = config.get('jitter', (0.01, 0.05))
        
    def init(self) -> bool:
        self.available = True  # Always available
        return True
    
    def is_available(self) -> bool:
        return True
    
    def encode_timing(self, data: str) -> list:
        """Bit-encode data into delays (higher density than bytes)"""
        bits = ''.join(format(ord(c), '08b') for c in data)
        delays = []
        for bit in bits:
            delay = self.base_delay * int(bit) + random.uniform(*self.jitter_range)
            delays.append(delay)
        return delays
    
    def send_command(self, command_data: dict, task_id: str) -> bool:
        encrypted = self.crypto.encrypt(command_data, task_id)
        delays = self.encode_timing(encrypted[:32])  # Limit size
        for delay in delays:
            time.sleep(delay)
        # Signal end with long pause
        time.sleep(1.0)
        return True
    
    def receive_response(self, task_id: str) -> dict:
        # Monitor incoming timings (e.g., via shared log or HTTP pings)
        # Simplified: Assume server logs delays
        pass  # CTF: Implement via beacon pings
    
    def beacon(self) -> bool:
        return self.send_command({'type': 'beacon'}, '')
    
    def teardown(self):
        pass
