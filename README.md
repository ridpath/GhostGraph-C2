GhostGraph C2 Framework
------------------------

> Modular, async, and covert C2 framework for red team operations and CTF challenges.
> Built for stealth, resilience, and multi-channel comms (ICMP, DNS, HTTP, Timing).
> 🚧 GhostGraph C2 is in alpha — expect instability. Use for CTFs, research, and red team experiments only.  
![status: alpha](https://img.shields.io/badge/status-alpha-orange)


------------------------

Features
------------------------

- Cross-platform implants (Linux, Windows, macOS) with platform-specific evasion and persistence
- Multi-channel fallback: ICMP, DNS, HTTP, Timing with priority-based hopping and health checks
- ChaCha20-Poly1305 + HMAC-SHA3 encryption for data in transit and at rest
- Anti-analysis: sandbox detection, debugger traps, VM heuristics, timing checks, and advanced evasion (e.g., LD_PRELOAD, IsDebuggerPresent, CPUID)
- Modular task engine: shell, download, upload, info, update with dynamic registry and command chaining
- Live self-updates: in-memory hot patching with HMAC validation and periodic polling
- Stealth profiles: process masquerading, output suppression, random delays, and obfuscation levels (XOR, shuffle, entropy)
- Secure file I/O: ChaCha20 encryption with 3-pass DoD-style deletion and secure overwrite
- Async dashboard built with Quart for high concurrency, with JWT/RBAC auth, WebSocket real-time, file upload/download, metrics, and HTML UI (webshell, upload form)
- CTF-proven architecture: modular configs, fast channel switching, and payload templates with validation/encoders
- FIPS/NIST-inspired design: key zeroization, system-bound identity, concealment mechanisms, and PBKDF2 hardening
- Adaptive scheduling with jitter, backoff, and time modulation for low-profile ops
- Comprehensive fingerprinting: OS/hardware/network/BIOS/CPUID/disk serial for unique IDs
- Persistence mechanisms: cron, registry, schtasks, launchagent with service disguises
- Server-side: Multi-protocol listener with metrics/backoff, command handler with DB/Redis for tasks/audits
- Top-level runner: CLI with Metasploit RPC integration, auto-update (git/download with sig verification), and mode switching
- OIDC support for external auth (e.g., Google/GitHub)
- Audit logging, CSV exports, and self-test endpoints for forensics and monitoring



------------------------

Architecture
------------------------

```
ghostgraph/
├── core/             # Crypto, scheduler, persistence, channel mgmt
├── channels/         # Covert channels (icmp, dns, http, timing, multi)
├── implants/         # Cross-platform implant logic (Linux, Windows, macOS)
├── server/           # Async C2 server, dashboard, DB-backed handler
├── tasks/            # Modular command implementations (shell, info, etc.)
├── utilities/        # Anti-analysis, fingerprinting, cleanup
├── config/           # CTF profiles and payload templates
├── ghostgraph.py     # Unified CLI entrypoint (server or implant)
├── main_implant.py   # Legacy implant runner (still supported)
├── main_server.py    # Legacy server runner (still supported)
├── requirements.txt  # Python package requirements
└── LICENSE           # MIT License

```

## ToDo / Roadmap

Upcoming feature tracks to evolve GhostGraph-C2 platform:

### 1. Malleable C2 Profiles
- Configurable HTTP/HTTPS profiles (jitter, headers, encoding).
- Template loader (`config/profiles/*.yaml`) with runtime transforms.
- Minimal changes to `channels/multi_channel.py`.

### 2. Advanced Post-Exploitation Modules
- New tasks: `cred_dump.py`, `keylog.py`, `lateral_move.py`, `privesc.py`.
- Registered via `TASK_HANDLERS` in `main_implant.py`.
- Modular additions: no core changes required.

### 3. Team Collaboration Features
- Real-time dashboards and shared sessions over WebSocket.
- Redis-backed pub/sub for `/collab/<session_id>`.
- Role upgrades for teams, operators, and viewers.

### 4. Plugin and Payload Extension System
- Dynamic plugin loading via `plugins/` and `plugin_manager.py`.
- Support for custom channels and tasks without forking.
- CLI payload builder with templating.

### 5. ML-Powered Adaptive Evasion
- Predictive beacon intervals via `ml_evasion.py`.
- Hooked into `timing_advanced.py` for adaptive patterns.
- Dashboard graphs using Chart.js under `/metrics_ui`.

### Additional Enhancements

- Mobile implant support (Android/iOS via Kivy or Frida)
- Serverless deployment modes (e.g., AWS Lambda, Cloudflare Workers)
- Automated payload generator (Obfuscator-IO + templates)
- Reporting export tools (`audit.csv`, implant logs in PDF)


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
GG_SECRET="your-shared-secret" python ghostgraph.py --mode server --profile stealth
```
Dashboard will be accessible at:
→ http://localhost:5000/implants
Supports profiles: stealth, aggressive, or a custom one via config/profiles.py

Optional:
Allowlist IPs: --allowed-ips 192.168.1.0/24
Set dashboard port: --port 8443
Adjust log level: --log-level DEBUG

Run the Implant
```bash
GG_SECRET="your-shared-secret" python ghostgraph.py --mode implant --profile stealth
```
Or use profiles: aggressive, stealth, or custom.
Will automatically select the correct implant based on OS: Linux, Windows, or macOS
Fully supports anti-analysis, persistence, and modular commands
Uses encrypted comms and self-update logic out of the box

Available Channels
------------------------

### Available Channels

| Channel   | Covert Method                        | Notes                                                                 |
|-----------|--------------------------------------|-----------------------------------------------------------------------|
| `icmp`    | ICMP Echo w/ fragmentation           | Raw sockets, supports fragmentation and out-of-order delivery         |
| `dns`     | DNS TXT & subdomain beaconing        | Obfuscated base32 + TXT response parsing; reliable in filtered nets   |
| `http`    | CSS comments + status code stego     | HTTP blending via `/update.css` and stealthy status signals           |
| `timing`  | Bit-delay encoding (timing channel)  | Sends data via bit-based delays; extremely low-bandwidth, hard to detect |
| `multi`   | Priority-based fallback & rotation   | Dynamically selects most available channel at runtime                |

Note: On multi-channel flow logic - channels are checked in priority order, all channels support encrypted, obfuscated data.

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

| Command     | Description                                 | Notes                                       |
|-------------|---------------------------------------------|---------------------------------------------|
| `info`      | Collect system fingerprint and metadata     | Uses platform-aware fingerprinting logic    |
| `shell`     | Execute shell command on target             | Captures stdout/stderr + exit code          |
| `download`  | Exfiltrate file from target (encrypted)     | Uses ChaCha20 + base64 + compression        |
| `upload`    | Upload file to target (encrypted)           | Uses ChaCha20 + base64; overwrites if exists|
| `update`    | Apply live code update from C2              | In-memory only, HMAC-verified, hot-loaded   |


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

GhostGraph implants include built-in anti-analysis logic to evade sandboxes, debuggers, and virtual machines.
All checks occur before persistence or C2 registration, with periodic re-checks during execution.

----- Debugger Detection -----
- Linux: Checks `/proc/self/status` for `TracerPid`
- Windows: Uses `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- macOS: Scans for `lldb`, `gdb`, suspicious parent processes

----- Virtualization Detection -----
- Looks for hypervisor strings in `/proc`, `/sys`, and BIOS/DMI
- Detects common platforms: QEMU, VirtualBox, VMware, Parallels

----- Timing-Based Anti-Debugging -----
- Uses high-resolution probes to detect breakpoints or step-throughs
- Fails fast if delays indicate instrumentation or patching

----- Kill Switch -----
- If `GG_KILL=1` is present in the environment, implant exits immediately
- Useful for CTF failsafe or controlled exits

----- Runtime Re-evaluation -----
- `AntiAnalysis().should_continue()` is re-run during the main loop
- If analysis is detected post-startup, the implant exits cleanly

----- Obfuscation and Delays -----
- Randomized delays (5–20s) on startup to frustrate sandboxes
- `stealth_level = high` disables stdout/stderr to reduce visibility


------------------------

------------------------
GhostGraph Dashboard (via Quart)
------------------------

The server and dashboard are now launched through the unified `ghostgraph.py` runner:

Start the Server:
```bash
python ghostgraph.py --mode server --profile stealth --secret your-shared-secret
```
Dashboard Interface:
→ Default port: http://localhost:5000/implants
→ Can be changed via --port or GG_PORT env

API Endpoints (Async-Ready):

GET /implants – List connected implants

POST /command/<implant_id> – Dispatch task to implant

GET /health – Health check endpoint

Notes:

All endpoints are fully async using Quart.

Use --allowed-ips to restrict dashboard access.

You can customize logging with --log-level.

------------------------

Payload Templates
------------------------

Located in: `config/payloads.py`

GhostGraph includes a powerful, extensible payload template system designed for: Red teaming, CTFs, pentesting, and evasion research

Supporting multiple platforms: Linux, Windows, macOS, and cross-platform

Generating payloads with defensive countermeasures, obfuscation, and encryption

Each payload template includes:

- Compiler flags for hardening (-static, -O3, /MT, etc.)

Obfuscation level and encoder:

- Supported: base64, zlib+base64, xor, aes-gcm, chacha20

Evasion techniques:

- Anti-debugging, polyglot formats (e.g., ELF + shell), dual-purpose binaries

Persistence strategies:

- cron, systemd, registry, launchagent, rootkits, schtasks

Command sets tailored per role (e.g., info, shell, upload, lateral_move)

Example Template:
```
PAYLOAD_TEMPLATES = {
    'linux_static': {
        'platform': 'linux',
        'compiler_flags': ['-static', '-O3', '-s', '-fPIC'],
        'obfuscation': {
            'level': 'medium',
            'encoder': 'chacha20'
        },
        'evasion': {
            'anti_debug': True,
            'polyglot': False
        },
        'commands': ['info', 'shell', 'download', 'upload'],
        'persistence': {
            'methods': ['cron', 'systemd'],
            'disguise': 'kernel-update.service'
        }
    }
}
```
Features:
- FIPS-compliant encryption (ChaCha20, AES-GCM)
- Multi-stage loader support
- Auto-queued commands based on fingerprinted OS
- Tamper detection via HMAC
- Overridable templates with validation and merging

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

