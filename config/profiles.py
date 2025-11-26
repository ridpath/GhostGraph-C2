# config/profiles.py
# Comprehensive configuration profiles for GhostGraph C2 framework
# Supports CTF scenarios with tunable behaviors for implants and servers.
# Loaded dynamically in main_implant.py and server/server.py.

# Implant-side profiles (CTF_PROFILES)
# These define behavior tuning for stealth vs. aggressive operations.
# Merged from all prior snippets: scheduler, channel, obfuscation, persistence, stealth_level.
# Defaults: self_update=False, log_jobs=True (overridable in main_implant.py).

CTF_PROFILES = {
    'stealth': {
        'scheduler': {
            'interval': 300,  # Longer beacons for low profile
            'jitter': 120
        },
        'channel': {
            'type': 'multi',
            'primary': 'dns',
            'fallback': 'timing'
        },
        'obfuscation': {
            'level': 'high'  # Full XOR/shuffle/entropy checks
        },
        'persistence': {
            'methods': ['cron']  # Linux-focused; extend for platforms
        },
        'stealth_level': 'high'  # Full hiding (process mask, delays, silence)
    },
    'aggressive': {
        'scheduler': {
            'interval': 30,  # Faster beacons for quick exfil
            'jitter': 10
        },
        'channel': {
            'type': 'icmp',
            'fragmentation': True  # Enable weird-sized packets
        },
        'obfuscation': {
            'level': 'low'  # Minimal to prioritize speed
        },
        'persistence': {
            'methods': ['service']  # Service/registry for Windows/Linux
        },
        'stealth_level': 'low'  # Basic hiding only
    }
}

# Server-side profiles (SERVER_PROFILES)
# Tuned for C2 listener/dashboard behaviors.
# Includes channel whitelisting, ports, and concurrency limits.

SERVER_PROFILES = {
    'stealth': {
        'channel': {
            'type': 'multi',
            'allowed_ips': ['192.168.1.0/24'],  # Whitelist for controlled envs
            'fragmentation': False  # Disable if not needed
        },
        'dashboard': {
            'port': 443,  # HTTPS-like for prod/CTF
            'ssl_enabled': True
        },
        'concurrency': {
            'max_concurrent': 100  # Handle multiple implants
        },
        'logging': {
            'level': 'INFO'  # Balanced for stealth
        }
    },
    'aggressive': {
        'channel': {
            'type': 'icmp',
            'allowed_ips': ['0.0.0.0/0'],  # Open for testing
            'fragmentation': True
        },
        'dashboard': {
            'port': 8080,
            'ssl_enabled': False
        },
        'concurrency': {
            'max_concurrent': 1000  # High for rapid ops
        },
        'logging': {
            'level': 'DEBUG'  # Verbose for troubleshooting
        }
    }
}

# Legacy flat configs (for backward compatibility with original config.py)
# Can be deprecated; use profiles instead.

IMPLANT_CONFIG_DEFAULT = {
    'shared_secret': 'your-shared-secret-here',
    'interval': 60,
    'channel': {
        'type': 'icmp',  # or 'timing'
        'target_ip': '192.168.1.100',
        'timeout': 2,
        'implant_id': 'agent-001'
    },
    'self_update': False,
    'log_jobs': True
}

SERVER_CONFIG_DEFAULT = {
    'shared_secret': 'your-shared-secret-here',
    'channels': ['icmp', 'timing'],
    'command_timeout': 30,
    'allowed_ips': ['192.168.1.0/24']
}
