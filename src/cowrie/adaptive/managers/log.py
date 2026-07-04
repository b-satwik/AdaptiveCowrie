# Adaptive Log Manager for Cowrie

import time
import random
from twisted.python import log
from cowrie.core.config import CowrieConfig

LOG_PATHS = (
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/kern.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/mysql/error.log"
)

class AdaptiveLogManager:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        self.seed_logs()

    def seed_logs(self):
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM system_logs WHERE profile_id = ?", (self.engine.active_profile_id,))
        if cursor.fetchone()[0] > 0:
            return

        log.msg("Seeding historical system logs, journal logs, and kernel logs in SQLite...")
        now = time.time()
        hostname = self.engine.persona_mgr.hostname
        p_name = self.engine.persona_mgr.active_persona

        # 1. Seed Auth History & auth.log
        auth_entries = [
            (now - 86400 * 3, "sshd", "failed", "Failed password for root from 203.0.113.5 port 45218 ssh2"),
            (now - 86400 * 2.8, "sshd", "failed", "Failed password for invalid user admin from 198.51.100.12 port 51004 ssh2"),
            (now - 86400 * 2, "sshd", "success", "Accepted password for root from 192.168.1.55 port 54321 ssh2"),
            (now - 86400 * 1.9, "sudo", "success", "root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get update"),
            (now - 86400 * 1.5, "sshd", "failed", "Failed password for root from 203.0.113.19 port 33142 ssh2"),
        ]

        if p_name == "amrita":
            auth_entries.append((now - 3600 * 5, "sshd", "success", "Accepted publickey for faculty from 192.168.1.10 port 49122 ssh2"))
            auth_entries.append((now - 3600 * 2, "sshd", "success", "Accepted password for student from 192.168.1.12 port 39822 ssh2"))
            auth_entries.append((now - 3600 * 1, "sudo", "success", "admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"))
        elif p_name == "university":
            auth_entries.append((now - 3600 * 5, "sshd", "success", "Accepted publickey for professor from 192.168.1.10 port 49122 ssh2"))
        elif p_name == "startup":
            auth_entries.append((now - 3600 * 3, "sshd", "success", "Accepted publickey for developer from 192.168.1.100 port 38812 ssh2"))

        for ts, service, status, msg in auth_entries:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            # Insert auth_history
            cursor.execute(
                """INSERT INTO auth_history (profile_id, timestamp, service, user, src_ip, status, message) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, t_str, service, "root", "192.168.1.55", status, msg)
            )
            # Insert system_logs
            cursor.execute(
                """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
                   VALUES (?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, "/var/log/auth.log", t_str, "auth", msg)
            )
            # Insert journal_logs
            cursor.execute(
                """INSERT INTO journal_logs (profile_id, timestamp, unit, syslog_identifier, pid, message) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, t_str, f"{service}.service", service, random.randint(500, 2000), msg)
            )

        # 2. Seed Syslog / General System Logs
        sys_entries = [
            (now - 86400 * 3, "/var/log/syslog", "syslog", "systemd[1]: Started LSB: automatic crash report generation."),
            (now - 86400 * 3, "/var/log/syslog", "syslog", "systemd[1]: Started Regular background program processing daemon."),
            (now - 86400 * 2.5, "/var/log/syslog", "syslog", "systemd[1]: Started OpenBSD Secure Shell server."),
            (now - 86400 * 2.1, "/var/log/syslog", "syslog", "systemd[1]: Starting Periodic Command Scheduler..."),
            (now - 86400 * 2.1, "/var/log/syslog", "syslog", "systemd[1]: Started Periodic Command Scheduler."),
        ]

        # Add hourly cron runs
        for i in range(24):
            ts = now - 3600 * i
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            msg = f"CRON[500{i%10}]: (root) CMD ([ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean)"
            sys_entries.append((ts, "/var/log/syslog", "cron", msg))

        for ts, path, facility, msg in sys_entries:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            cursor.execute(
                """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
                   VALUES (?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, path, t_str, facility, msg)
            )
            cursor.execute(
                """INSERT INTO journal_logs (profile_id, timestamp, unit, syslog_identifier, pid, message) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, t_str, f"{facility}.service", facility, random.randint(400, 1500), msg)
            )

        # 3. Seed Kernel Logs (dmesg)
        kernel_messages = [
            "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-013) (gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04) )",
            "Command line: BOOT_IMAGE=/vmlinuz-5.15.0-88-generic root=UUID=a217b1d2 ro quiet splash",
            "x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'",
            "BIOS-provided physical RAM map:",
            "BIOS-e820: [mem 0x0000000000000000-0x000000000009ffff] usable",
            "BIOS-e820: [mem 0x0000000000100000-0x000000007fffffff] usable",
            "ACPI: Core revision 20210604",
            "hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0",
            "SMP: Allowing 4 CPUs, 0 hotplug CPUs",
            "Performance Events: PMU not available due to virtualization, using software events only.",
            "devtmpfs: initialized",
            "Clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x3156cf387f3, max_idle_ns: 440795276378 ns",
            "VFS: Disk quotas dquot_1.6.0",
            "VFS: Loaded ext4 filesystem driver",
            "SCSI subsystem initialized",
            "ACPI: bus type PCI registered",
            "PCI: Using configuration type 1 for base access",
            "libata version 3.00 loaded.",
            "ahci 0000:00:1f.2: version 3.0",
            "ata1: SATA link up 6.0 Gbps (cssn 0.1s)",
            "ata1.00: ATA-9: QEMU HARDDISK, 2.5+, max UDMA/100",
            "ata1.00: 83886080 sectors, multi 16, FUA",
            "ata1.00: configured for UDMA/100",
            "scsi 0:0:0:0: Direct-Access     ATA      QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5",
            "sd 0:0:0:0: [sda] 83886080 512-byte logical blocks: (42.9 GB/40.0 GiB)",
            "sd 0:0:0:0: [sda] Write Protect is off",
            "sd 0:0:0:0: [sda] Mode Sense: 00 00 00 00",
            "sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA",
            " sda: sda1 sda2",
            "sd 0:0:0:0: [sda] Attached SCSI disk",
            "EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null). Quota mode: none.",
            "NET: Registered PF_INET6 protocol family",
            "Segment Routing with IPv6",
            "RPC: Registered named UNIX socket transport module.",
            "input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/serio1/input/input3",
            "e1000: Intel(R) PRO/1000 Network Connection",
            "e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection",
            "e1000 0000:00:03.0 eth0: MAC: 52:54:00:12:34:56, Link is Up 1000 Mbps Full Duplex",
            "sd 0:0:0:0: [sda] ALUA state: Active/Optimized",
            "VMware hypervisor detected.",
            "VMware vmmouse: Probing vmmouse...",
            "VMware vmmouse: Enabled vmmouse at serio1",
            "Docker startup: docker0 bridge interface created.",
            "FS-Cache: Loaded",
            "Key type dns_resolver registered",
            "fuse: init (API version 7.34)",
            "systemd[1]: Inserted module 'autofs4'"
        ]

        uptime_offset = 0.015
        for msg in kernel_messages:
            cursor.execute(
                "INSERT INTO kernel_logs (profile_id, uptime_sec, message) VALUES (?, ?, ?)",
                (self.engine.active_profile_id, uptime_offset, msg)
            )
            # Also insert kernel messages into system_logs (kern.log)
            k_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 86400 * 2.9 + uptime_offset))
            cursor.execute(
                """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
                   VALUES (?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, "/var/log/kern.log", k_time_str, "kernel", f"kernel: [{uptime_offset:12.6f}] {msg}")
            )
            uptime_offset += random.uniform(0.005, 0.1)

        # 4. Seed Web Server (Nginx / Apache) & MySQL Logs
        web_logs = [
            ("/var/log/nginx/access.log", "nginx", "192.168.1.55 - - [01/Jul/2026:10:25:01 +0000] \"GET / HTTP/1.1\" 200 3426 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\""),
            ("/var/log/nginx/error.log", "nginx", "2026/07/01 10:25:01 [notice] 1042#1042: using the \"epoll\" event method"),
            ("/var/log/apache2/access.log", "apache2", "192.168.1.55 - - [01/Jul/2026:10:25:02 +0000] \"GET /portal HTTP/1.1\" 200 4812"),
            ("/var/log/apache2/error.log", "apache2", "[Wed Jul 01 10:25:02.124561 2026] [mpm_event:notice] [pid 1001:tid 14003] AH00489: Apache/2.4.52 (Ubuntu) configured"),
            ("/var/log/mysql/error.log", "mysql", "2026-07-01T10:24:10.124856Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld (mysqld 8.0.33) starting as process 1089"),
        ]

        for path, facility, msg in web_logs:
            cursor.execute(
                """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
                   VALUES (?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, path, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 3600)), facility, msg)
            )

        self.engine.conn.commit()

    def add_auth_log(self, service: str, user: str, src_ip: str, status: str, message: str):
        cursor = self.engine.conn.cursor()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """INSERT INTO auth_history (profile_id, timestamp, service, user, src_ip, status, message) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, t_str, service, user, src_ip, status, message)
        )
        cursor.execute(
            """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
               VALUES (?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "/var/log/auth.log", t_str, "auth", message)
        )
        cursor.execute(
            """INSERT INTO journal_logs (profile_id, timestamp, unit, syslog_identifier, pid, message) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, t_str, f"{service}.service", service, random.randint(500, 2000), message)
        )
        self.engine.conn.commit()

    def add_system_log(self, log_path: str, facility: str, log_line: str):
        cursor = self.engine.conn.cursor()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """INSERT INTO system_logs (profile_id, log_path, timestamp, facility, log_line) 
               VALUES (?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, log_path, t_str, facility, log_line)
        )
        cursor.execute(
            """INSERT INTO journal_logs (profile_id, timestamp, unit, syslog_identifier, pid, message) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, t_str, f"{facility}.service", facility, random.randint(400, 1500), log_line)
        )
        self.engine.conn.commit()

    def generate_log_content(self, path: str) -> bytes:
        cursor = self.engine.conn.cursor()
        hostname = self.engine.persona_mgr.hostname
        
        if path == "/var/log/auth.log":
            cursor.execute("SELECT * FROM system_logs WHERE log_path = ? AND is_deleted = 0 AND profile_id = ? ORDER BY id ASC", (path, self.engine.active_profile_id))
            lines = []
            for row in cursor.fetchall():
                dt = time.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                date_str = time.strftime("%b %e %H:%M:%S", dt)
                lines.append(f"{date_str} {hostname} {row['log_line']}\n")
            return "".join(lines).encode()

        elif path in ("/var/log/syslog", "/var/log/messages"):
            cursor.execute("SELECT * FROM system_logs WHERE log_path = ? AND is_deleted = 0 AND profile_id = ? ORDER BY id ASC", (path, self.engine.active_profile_id))
            lines = []
            for row in cursor.fetchall():
                dt = time.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                date_str = time.strftime("%b %e %H:%M:%S", dt)
                lines.append(f"{date_str} {hostname} {row['log_line']}\n")
            return "".join(lines).encode()

        elif path == "/var/log/kern.log":
            cursor.execute("SELECT * FROM system_logs WHERE log_path = ? AND is_deleted = 0 AND profile_id = ? ORDER BY id ASC", (path, self.engine.active_profile_id))
            lines = []
            for row in cursor.fetchall():
                dt = time.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                date_str = time.strftime("%b %e %H:%M:%S", dt)
                lines.append(f"{date_str} {hostname} {row['log_line']}\n")
            return "".join(lines).encode()

        elif path in LOG_PATHS:
            cursor.execute("SELECT * FROM system_logs WHERE log_path = ? AND is_deleted = 0 AND profile_id = ? ORDER BY id ASC", (path, self.engine.active_profile_id))
            rows = cursor.fetchall()
            return "".join([f"{r['log_line']}\n" for r in rows]).encode()

        return b""

    def handle_log_write(self, path: str, content: bytes):
        """Processes attacker actions affecting logs like truncation, sed edits, etc."""
        cursor = self.engine.conn.cursor()
        
        # Check if content is empty or truncate occurred
        stripped = content.strip()
        if len(stripped) == 0 or stripped == b"" or stripped == b"\n":
            log.msg(f"Anti-forensics log clearing detected on: {path}")
            
            # Fetch current content before deletion for hidden telemetry preservation
            orig_content = self.generate_log_content(path)
            session_id = "unknown"
            
            # Log clearing attempt in telemetry
            self.engine.telemetry_mgr.log_event(
                session_id=session_id,
                event_type="anti_forensics_log_clear",
                command=f"truncate/clear {path}",
                details=f"Log cleared. Previous lines count: {len(orig_content.split(b'\n')) - 1}",
                mitre_tag="T1070.002",
                risk_score=60
            )

            # Mark in SQLite tables
            cursor.execute("UPDATE system_logs SET is_deleted = 1 WHERE log_path = ? AND profile_id = ?", (path, self.engine.active_profile_id))
            if path in ("/var/log/syslog", "/var/log/auth.log"):
                cursor.execute("UPDATE journal_logs SET is_deleted = 1 WHERE profile_id = ?", (self.engine.active_profile_id,))
            self.engine.conn.commit()

            # Empty file content in SQLite VFS
            cursor.execute("INSERT OR REPLACE INTO file_contents (profile_id, path, content) VALUES (?, ?, ?)", (self.engine.active_profile_id, path, b""))
            self.engine.conn.commit()
            return

        # It's an edit or write (e.g. sed modifications)
        log.msg(f"Attacker modified log file: {path} for profile {self.engine.active_profile_id}")
        cursor.execute("INSERT OR REPLACE INTO file_contents (profile_id, path, content) VALUES (?, ?, ?)", (self.engine.active_profile_id, path, content))
        self.engine.conn.commit()
