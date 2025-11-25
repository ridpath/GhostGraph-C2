import time
import random
import math

class AdaptiveScheduler:
    def __init__(self, config: dict):
        self.base_interval = config.get('interval', 60)
        self.max_jitter = config.get('jitter', 30)
        self.fail_count = 0
        self.last_success = time.time()
        
    def calculate_delay(self) -> float:
        """Exponential backoff + jitter + time modulation"""
        backoff = min(math.pow(2, self.fail_count), 3600)
        jitter = random.uniform(-self.max_jitter, self.max_jitter)
        hour = time.localtime().tm_hour
        modulation = 60 if 9 <= hour <= 17 else 0  # Slower in business hours
        return (self.base_interval * backoff) + jitter + modulation
    
    def record_success(self):
        self.fail_count = max(0, self.fail_count - 1)
        self.last_success = time.time()
    
    def record_failure(self):
        self.fail_count += 1
    
    def sleep_until_next(self):
        time.sleep(max(1, self.calculate_delay()))  # Min 1s
