import json
import random
import math

class DataObfuscator:
    def __init__(self):
        self.entropy_threshold = 7.0  # Shannon entropy
        
    def obfuscate(self, data: bytes) -> bytes:
        """XOR + chunk shuffle if low entropy"""
        if self._calculate_entropy(data) < self.entropy_threshold:
            # Shuffle chunks
            chunk_size = random.randint(8, 32)
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            random.shuffle(chunks)
            data = b''.join(chunks)
        # XOR layer
        xor_key = random.randbytes(16)
        return bytes(a ^ b for a, b in zip(data, xor_key * (len(data) // 16 + 1))) + xor_key
    
    def deobfuscate(self, data: bytes) -> bytes:
        """Reverse shuffle + XOR"""
        xor_key = data[-16:]
        data = data[:-16]
        data = bytes(a ^ b for a, b in zip(data, xor_key * (len(data) // 16 + 1)))
        # Reassemble chunks (assume fixed order or metadata; simplified for CTF)
        return data  # In prod, add chunk metadata
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Shannon entropy to detect repetitive patterns"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
    
    def shuffle_json_keys(self, data: dict) -> str:
        """Randomize JSON keys"""
        items = list(data.items())
        random.shuffle(items)
        return json.dumps(dict(items), separators=(',', ':'))
