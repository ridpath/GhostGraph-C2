GhostGraph C2 Framework
------------------------

> Modular, async, and covert C2 framework for red team operations and CTF challenges.
> Built for stealth, resilience, and multi-channel comms (ICMP, DNS, HTTP, Timing).
> 🚧 Graphless C2 is in alpha — expect instability. Use for CTFs, research, and red team experiments only.  
![status: alpha](https://img.shields.io/badge/status-alpha-orange)


------------------------

Features
------------------------

**Async & Non-blocking** implant-to-server comms  
**Multi-channel Fallback:** ICMP, DNS, HTTP stego, Timing  
**ChaCha20 + HMAC-SHA3** encryption with context-aware KDF  
**Data Obfuscation:** XOR + shuffle + compression  
**Fragmentation & Padding** for ICMP stealth  
**Profile-based Config** for stealth/aggressive tuning  
**Anti-analysis** (VM + Debugger + Timing checks)  
**Flask/Quart Dashboard** for live command control  
**Cross-platform** support (Linux & Windows implants)

------------------------

Architecture
------------------------

```
ghostgraph/
├── core/             # Crypto, scheduler, channels, obfuscation
├── channels/         # Covert channels (icmp, dns, http, timing)
├── implants/         # Implant logic
├── server/           # Async server, listener, dashboard
├── utilities/        # Anti-analysis, fingerprinting
├── config/           # Profiles and payloads
├── main_implant.py   # Implant runner
├── main_server.py    # Server runner
└── requirements.txt
```



------------------------

Quick Start
------------------------

**Install Requirements**

```bash
pip install -r requirements.txt
```
Run the Server (with Dashboard)
------------------------

```bash
GG_SECRET="your-shared-secret" GG_PROFILE=stealth python server/server.py
```
Dashboard will be accessible at:
→ http://localhost:5000/implants

Run the Implant
```bash
GG_SECRET="your-shared-secret" python main_implant.py stealth
```
Or use profiles: aggressive, stealth, or custom.

Available Channels
------------------------

| Channel | Covert Method                 | Notes                             |
|---------|-------------------------------|-----------------------------------|
| `icmp`  | ICMP Echo w/ fragmentation    | Needs raw socket, very stealthy   |
| `dns`   | DNS TXT or subdomain beacon   | Works well in most environments   |
| `http`  | CSS comments, status stego    | Blends in with legit web traffic  |
| `timing`| Bit-delay timing patterns     | Low bandwidth, highly covert      |
| `multi` | Fallback + hopping            | Prioritized channel selection     |

------------------------

CTF Profiles
------------------------

Located in: `config/profiles.py`

```python
CTF_PROFILES = {
    'stealth': {
        'scheduler': {'interval': 300, 'jitter': 120},
        'channel': {'type': 'multi', 'primary': 'dns', 'fallback': 'timing'},
        'obfuscation': {'level': 'high'},
        'persistence': {'methods': ['cron']}
    },
    'aggressive': {
        'scheduler': {'interval': 30, 'jitter': 10},
        'channel': {'type': 'icmp', 'fragmentation': True},
        'obfuscation': {'level': 'low'},
        'persistence': {'methods': ['service']}
    }
}
```
To use a profile:
```bash
python main_implant.py stealth
```

Supported Implant Commands
------------------------

| Command     | Description                        |
|-------------|------------------------------------|
| `info`      | Collects system fingerprint        |
| `shell`     | Executes a shell command           |
| `upload`    | *(Planned)* Upload file to host    |
| `download`  | *(Planned)* Download file from host|

All commands are task‑based and trackable via the dashboard.

------------------------

Encryption Design
------------------------

- **Cipher:** ChaCha20Poly1305  
- **Auth:** HMAC‑SHA3‑256  
- **KDF:** PBKDF2‑HMAC‑SHA3 (contextual salt using system ID + task ID)  
- **Obfuscation:** XOR with session token + randomized JSON key order  
- **Compression:** zlib‑ng prior to encryption  

**Payload Format:**
version + salt + nonce + hmac + ciphertext

------------------------

Implant Anti‑Analysis
------------------------

- Detects debuggers (`/proc/self/status`, Windows APIs)
- Virtualization detection (`/proc`, `/sys`, hypervisor strings)
- Timing‑based anti‑debug heuristics
- Randomized jitter + adaptive scheduling for stealth

------------------------

Flask Dashboard (via Quart)
------------------------

Start the dashboard server:

```bash
python server/server.py
```
API Endpoints
------------------------

- `GET /implants` – List connected agents  
- `POST /command/<implant_id>` – Send a command  
- `GET /health` – Health check  

All endpoints are **async-compatible** for high concurrency.

------------------------

Payload Templates
------------------------

Located in: `config/payloads.py`

```python
PAYLOAD_TEMPLATES = {
    'ctf_beacon': {
        'commands': ['info', 'shell'],
        'encoder': 'base64 + zlib'
    }
}
```
------------------------
Security Notes
------------------------
For educational and authorized security testing only.
Do NOT use on any system you do not own or lack explicit permission to test.
Improper use is illegal and entirely the responsibility of the user.

------------------------
License
------------------------

This project is licensed under the [MIT License](LICENSE).

> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.

