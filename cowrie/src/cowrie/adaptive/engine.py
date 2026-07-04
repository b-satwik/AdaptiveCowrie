# Adaptive Deception Engine for Cowrie

import os
import sqlite3
from twisted.python import log
from cowrie.core.config import CowrieConfig

class AdaptiveEngine:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.enabled = CowrieConfig.getboolean("adaptive", "enabled", fallback=False)
        if not self.enabled:
            return

        self.db_path = CowrieConfig.get("adaptive", "database", fallback="var/lib/cowrie/adaptive_cowrie.db")
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        # Initialize individual managers
        self.init_managers()
        # Create SQLite tables
        self.init_db()

    @property
    def active_profile_id(self):
        return getattr(self, "_active_profile_id", "default")

    @active_profile_id.setter
    def active_profile_id(self, val):
        self._active_profile_id = val

    def init_managers(self):
        from cowrie.adaptive.managers.filesystem import AdaptiveFilesystemManager
        from cowrie.adaptive.managers.persona import AdaptivePersonaManager
        from cowrie.adaptive.managers.log import AdaptiveLogManager
        from cowrie.adaptive.managers.process import AdaptiveProcessManager
        from cowrie.adaptive.managers.service import AdaptiveServiceManager
        from cowrie.adaptive.managers.user import AdaptiveUserManager
        from cowrie.adaptive.managers.network import AdaptiveNetworkManager
        from cowrie.adaptive.managers.telemetry import AdaptiveTelemetryManager
        from cowrie.adaptive.managers.honeytoken import AdaptiveHoneytokenManager
        from cowrie.adaptive.managers.behavior import AdaptiveBehaviorProfiler

        self.fs_mgr = AdaptiveFilesystemManager(self)
        self.persona_mgr = AdaptivePersonaManager(self)
        self.log_mgr = AdaptiveLogManager(self)
        self.process_mgr = AdaptiveProcessManager(self)
        self.service_mgr = AdaptiveServiceManager(self)
        self.user_mgr = AdaptiveUserManager(self)
        self.network_mgr = AdaptiveNetworkManager(self)
        self.telemetry_mgr = AdaptiveTelemetryManager(self)
        self.honeytoken_mgr = AdaptiveHoneytokenManager(self)
        self.behavior_profiler = AdaptiveBehaviorProfiler(self)
        from cowrie.adaptive.managers.memory import AdaptiveMemoryManager
        self.memory_mgr = AdaptiveMemoryManager(self)
        self.memory_mgr.start()
        from cowrie.adaptive.managers.mitre import MITREAttackManager
        from cowrie.adaptive.managers.threat import ThreatScoreManager
        self.mitre_mgr = MITREAttackManager(self)
        self.threat_mgr = ThreatScoreManager(self)
        self.mitre_mgr.start()
        self.threat_mgr.start()

    def init_db(self):
        cursor = self.conn.cursor()

        # Check if schema needs upgrade (i.e. profile_id is missing from filesystem table)
        schema_upgrade_needed = False
        try:
            cursor.execute("SELECT profile_id FROM filesystem LIMIT 1")
        except sqlite3.OperationalError:
            # Table exists but column missing, or table doesn't exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='filesystem'")
            if cursor.fetchone():
                schema_upgrade_needed = True

        if schema_upgrade_needed:
            log.msg("Upgrading Adaptive Deception DB to support profile isolation...")
            # Drop old tables to recreate them with the correct schema
            tables_to_drop = [
                "filesystem", "file_contents", "system_services", "system_processes", 
                "users", "auth_history", "system_logs", "telemetry", "journal_logs", 
                "kernel_logs", "bash_history", "last_logins", "network_interfaces",
                "network_routes", "network_sockets"
            ]
            for tbl in tables_to_drop:
                try:
                    cursor.execute(f"DROP TABLE IF EXISTS {tbl}")
                except Exception:
                    pass
            self.conn.commit()

        # 1. Filesystem table (extended with metadata & profile_id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS filesystem (
                profile_id TEXT,
                path TEXT,
                parent TEXT,
                name TEXT,
                type INTEGER,
                uid INTEGER,
                gid INTEGER,
                size INTEGER,
                mode INTEGER,
                ctime REAL,
                mtime REAL,
                atime REAL,
                inode INTEGER,
                nlink INTEGER,
                target TEXT,
                realfile TEXT,
                PRIMARY KEY (profile_id, path)
            )
        """)

        # Create indexes for quick lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fs_parent ON filesystem(profile_id, parent)")

        # 2. File contents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_contents (
                profile_id TEXT,
                path TEXT,
                content BLOB,
                PRIMARY KEY (profile_id, path)
            )
        """)

        # 3. Simulated services table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_services (
                profile_id TEXT,
                name TEXT,
                status TEXT, -- active, inactive, failed
                pid INTEGER,
                uptime REAL,
                PRIMARY KEY (profile_id, name)
            )
        """)

        # 4. Simulated processes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_processes (
                profile_id TEXT,
                pid INTEGER,
                user TEXT,
                cpu REAL,
                mem REAL,
                vsz INTEGER,
                rss INTEGER,
                tty TEXT,
                stat TEXT,
                start TEXT,
                time TEXT,
                command TEXT,
                PRIMARY KEY (profile_id, pid)
            )
        """)

        # 5. Simulated users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                profile_id TEXT,
                username TEXT,
                uid INTEGER,
                gid INTEGER,
                home TEXT,
                shell TEXT,
                groups TEXT,
                password_hash TEXT,
                last_login TEXT,
                password TEXT,
                gecos TEXT,
                PRIMARY KEY (profile_id, username)
            )
        """)

        # 6. Auth history logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                timestamp TEXT,
                service TEXT,
                user TEXT,
                src_ip TEXT,
                status TEXT,
                message TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_hist_prof ON auth_history(profile_id)")

        # 7. System logs table (extended with facility/is_deleted)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                log_path TEXT,
                timestamp TEXT,
                facility TEXT,
                log_line TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sys_logs_prof ON system_logs(profile_id)")

        # 8. Detailed Telemetry table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                session_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                command TEXT,
                cwd TEXT,
                details TEXT,
                mitre_tag TEXT,
                risk_score INTEGER
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_prof ON telemetry(profile_id)")

        # 9. Journal logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS journal_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                timestamp TEXT,
                unit TEXT,
                syslog_identifier TEXT,
                pid INTEGER,
                message TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_logs_prof ON journal_logs(profile_id)")

        # 10. Kernel logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kernel_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                uptime_sec REAL,
                message TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kernel_logs_prof ON kernel_logs(profile_id)")

        # 11. Bash command history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bash_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                username TEXT,
                session_id TEXT,
                command TEXT,
                timestamp REAL,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bash_hist_prof ON bash_history(profile_id)")

        # 12. Last logins table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS last_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                username TEXT,
                tty TEXT,
                ip TEXT,
                login_time REAL,
                logout_time REAL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_last_logins_prof ON last_logins(profile_id)")

        # 13. Network interfaces table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_interfaces (
                profile_id TEXT,
                name TEXT,
                ip TEXT,
                netmask TEXT,
                mac TEXT,
                rx_bytes INTEGER,
                tx_bytes INTEGER,
                PRIMARY KEY (profile_id, name)
            )
        """)

        # 14. Network routes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                destination TEXT,
                gateway TEXT,
                genmask TEXT,
                flags TEXT,
                metric INTEGER,
                ref INTEGER,
                use INTEGER,
                iface TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_routes_prof ON network_routes(profile_id)")

        # 15. Network sockets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_sockets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT,
                proto TEXT,
                local_addr TEXT,
                remote_addr TEXT,
                state TEXT,
                pid INTEGER,
                program TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_sockets_prof ON network_sockets(profile_id)")

        # 16. Session metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_metrics (
                session_id TEXT PRIMARY KEY,
                start_time REAL,
                duration REAL DEFAULT 0.0,
                commands_count INTEGER DEFAULT 0,
                dirs_explored TEXT DEFAULT '[]',
                files_created TEXT DEFAULT '[]',
                files_modified TEXT DEFAULT '[]',
                honeytokens_tripped INTEGER DEFAULT 0,
                priv_esc_attempts INTEGER DEFAULT 0,
                risk_score_evolution TEXT DEFAULT '[]',
                mitre_attack_techniques TEXT DEFAULT '[]'
            )
        """)

        # 17. Attacker profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                profile_id TEXT PRIMARY KEY,
                first_seen REAL,
                last_seen REAL,
                persona TEXT,
                fingerprint_hash TEXT,
                confidence REAL,
                expires_at REAL
            )
        """)

        # 18. Profile sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profile_sessions (
                session_id TEXT PRIMARY KEY,
                profile_id TEXT,
                ttylog_path TEXT,
                login_time REAL,
                logout_time REAL,
                src_ip TEXT,
                ssh_client TEXT
            )
        """)

        # 19. Profile metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profile_metadata (
                profile_id TEXT PRIMARY KEY,
                last_username TEXT,
                last_hostname TEXT,
                risk_score REAL,
                behavior_summary TEXT
            )
        """)

        # 20. MITRE mappings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                profile_id TEXT,
                command TEXT,
                technique TEXT,
                tactic TEXT,
                confidence REAL,
                timestamp REAL
            )
        """)

        # 21. Profile behavior features table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profile_behavior_features (
                profile_id TEXT PRIMARY KEY,
                ssh_key TEXT,
                username TEXT,
                client_banner TEXT,
                src_ip TEXT,
                first_n_commands TEXT,
                command_sequence_similarity REAL,
                recon_score REAL,
                credential_access_score REAL,
                privilege_escalation_score REAL,
                persistence_score REAL,
                discovery_score REAL,
                honeytoken_interactions INTEGER,
                filesystem_traversal INTEGER,
                service_modifications INTEGER,
                uploads INTEGER,
                downloads INTEGER,
                session_duration REAL,
                commands_executed INTEGER,
                failed_commands INTEGER,
                idle_time REAL,
                created_files_revisited INTEGER,
                created_dirs_revisited INTEGER,
                installed_persistence_revisited INTEGER,
                created_users_revisited INTEGER,
                modified_services_revisited INTEGER
            )
        """)

        self.conn.commit()
        log.msg("Adaptive Deception Engine database tables initialized successfully.")
