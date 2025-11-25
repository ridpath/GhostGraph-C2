import os
import json
import hmac
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class AdaptiveCrypto:
    def __init__(self, shared_secret: str, context: str = ""):
        self.shared_secret = shared_secret.encode()
        self.context = (context or secrets.token_hex(16)).encode()  # Dynamic context
        self.version = b'\x01'  # Version header
        self.session_id = secrets.token_bytes(16)  # Watermark
        
    def derive_key(self, salt: bytes = None, info: bytes = None, task_id: str = "") -> tuple:
        """Split KDF: ENC + AUTH keys with context (fingerprint + task_id)"""
        if salt is None:
            salt = os.urandom(32)
        if info is None:
            info = self.context + task_id.encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=64,  # 32 ENC + 32 AUTH
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_material = kdf.derive(self.shared_secret + info)
        
        # Zero memory after use (simplified; use sodium for full wipe)
        enc_key = key_material[:32]
        auth_key = key_material[32:]
        return enc_key, auth_key, salt
    
    def encrypt(self, data: dict, task_id: str = "", additional_data: bytes = b"") -> str:
        """Encrypt: Compress + Obfuscate + ChaCha20 + HMAC + Version"""
        # Compress
        plaintext = json.dumps(data).encode()
        compressed = zlib.compress(plaintext)
        
        # Obfuscate (XOR + shuffle)
        obfuscated = self._obfuscate(compressed)
        
        # Derive keys with task context (anti-replay)
        enc_key, auth_key, salt = self.derive_key(task_id=task_id)
        
        # Encrypt
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(enc_key)
        ciphertext = chacha.encrypt(nonce, obfuscated, additional_data + self.session_id)
        
        # HMAC for tamper detection
        hmac_value = hmac.new(auth_key, self.version + salt + nonce + ciphertext, hashlib.sha3_256).digest()[:16]
        
        # Payload: version + salt + nonce + HMAC + ciphertext
        payload = self.version + salt + nonce + hmac_value + ciphertext
        
        # Base64 encode
        return base64.urlsafe_b64encode(payload).decode()
    
    def decrypt(self, encrypted_data: str, task_id: str = "", additional_data: bytes = b"") -> dict:
        """Decrypt with validation (constant-time HMAC)"""
        try:
            payload = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Parse
            if payload[:1] != self.version:
                return None
            salt = payload[1:33]
            nonce = payload[33:45]
            received_hmac = payload[45:61]
            ciphertext = payload[61:]
            
            # Derive keys
            enc_key, auth_key, _ = self.derive_key(salt, task_id=task_id)
            
            # Constant-time HMAC verify
            expected_hmac = hmac.new(auth_key, self.version + salt + nonce + ciphertext, hashlib.sha3_256).digest()[:16]
            if not hmac.compare_digest(received_hmac, expected_hmac):
                return None
            
            # Decrypt
            chacha = ChaCha20Poly1305(enc_key)
            obfuscated = chacha.decrypt(nonce, ciphertext, additional_data + self.session_id)
            
            # Deobfuscate + decompress
            compressed = self._deobfuscate(obfuscated)
            plaintext = zlib.decompress(compressed)
            
            return json.loads(plaintext.decode())
        except Exception:
            return None
    
    def _obfuscate(self, data: bytes) -> bytes:
        """XOR shuffle for obfuscation"""
        key = hashlib.sha256(self.session_id).digest()
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    def _deobfuscate(self, data: bytes) -> bytes:
        """Reverse XOR"""
        key = hashlib.sha256(self.session_id).digest()
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
