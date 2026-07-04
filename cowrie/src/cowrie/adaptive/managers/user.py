# Adaptive User Manager for Cowrie

import time
from twisted.python import log

class AdaptiveUserManager:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        self.seed_users()
        self.seed_last_logins()

    def seed_users(self):
        cursor = self.engine.conn.cursor()
        
        # Re-check columns in SQLite users table
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN password TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN gecos TEXT")
        except Exception:
            pass

        log.msg("Seeding system users in SQLite...")
        
        # Standard users
        users = [
            ("root", "x", 0, 0, "root", "/root", "/bin/bash", "root"),
            ("daemon", "x", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin", "daemon"),
            ("bin", "x", 2, 2, "bin", "/bin", "/usr/sbin/nologin", "bin"),
            ("sys", "x", 3, 3, "sys", "/dev", "/usr/sbin/nologin", "sys"),
            ("sync", "x", 4, 65534, "sync", "/bin", "/bin/sync", "nogroup"),
            ("games", "x", 5, 60, "games", "/usr/games", "/usr/sbin/nologin", "games"),
            ("man", "x", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin", "man"),
            ("lp", "x", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin", "lp"),
            ("mail", "x", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin", "mail"),
            ("news", "x", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin", "news"),
            ("uucp", "x", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin", "uucp"),
            ("proxy", "x", 13, 13, "proxy", "/bin", "/usr/sbin/nologin", "proxy"),
            ("www-data", "x", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin", "www-data"),
            ("backup", "x", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin", "backup"),
            ("list", "x", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin", "list"),
            ("irc", "x", 39, 39, "ircd", "/run/ircd", "/usr/sbin/nologin", "irc"),
            ("gnats", "x", 41, 41, "Gnats Bug-Reporting System (admin)", "/var/lib/gnats", "/usr/sbin/nologin", "gnats"),
            ("nobody", "x", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin", "nogroup"),
            ("systemd-network", "x", 100, 102, "systemd Network Management", "/run/systemd", "/usr/sbin/nologin", "systemd-journal"),
            ("systemd-resolve", "x", 101, 103, "systemd Resolver", "/run/systemd", "/usr/sbin/nologin", "systemd-journal"),
            ("messagebus", "x", 102, 104, "", "/nonexistent", "/usr/sbin/nologin", "messagebus"),
            ("sshd", "x", 103, 65534, "", "/run/sshd", "/usr/sbin/nologin", "nogroup"),
        ]

        # Add persona specific users
        p_name = self.engine.persona_mgr.active_persona
        if p_name == "amrita":
            users.append(("admin", "x", 1001, 1001, "Administrator", "/home/admin", "/bin/bash", "admin,sudo,wheel"))
            users.append(("faculty", "x", 1002, 1002, "Amrita Faculty", "/home/faculty", "/bin/bash", "faculty,shared"))
            users.append(("research", "x", 1003, 1003, "Amrita Researcher", "/home/research", "/bin/bash", "research,shared"))
            users.append(("student", "x", 1004, 1004, "Amrita Student", "/home/student", "/bin/sh", "student"))
            users.append(("placement", "x", 1005, 1005, "Amrita Placement Officer", "/home/placement", "/bin/bash", "placement,shared"))
            users.append(("backup-user", "x", 1006, 1006, "SysOps Backup", "/home/backup", "/bin/sh", "backup"))
        elif p_name == "university":
            users.append(("professor", "x", 1001, 1001, "Professor Jones", "/home/professor", "/bin/bash", "professor,faculty,shared"))
            users.append(("gradstudent", "x", 1002, 1002, "Graduate Student", "/home/gradstudent", "/bin/bash", "gradstudent,shared"))
            users.append(("registrar", "x", 1003, 1003, "Registrar", "/home/registrar", "/bin/sh", "registrar,staff"))

        import hashlib
        salt = "salt123"
        default_passwords = {
            "root": "Root@2026",
            "admin": "Admin@2026",
            "faculty": "Faculty@2026",
            "research": "Research@2026",
            "student": "Student@2026",
            "placement": "Placement@2026",
            "backup-user": "Backup@2026",
            "backup": "Backup@2026",
            "professor": "Professor@2026",
            "gradstudent": "Gradstudent@2026",
            "registrar": "Registrar@2026"
        }

        for username, password, uid, gid, gecos, home, shell, groups in users:
            pwd_hash = "!!"
            if username in default_passwords and not shell.endswith("/usr/sbin/nologin") and not shell.endswith("/bin/sync"):
                pwd_hash = hashlib.sha512((default_passwords[username] + salt).encode()).hexdigest()

            # Insert or update
            cursor.execute("SELECT password_hash FROM users WHERE username = ? AND profile_id = ?", (username, self.engine.active_profile_id))
            row = cursor.fetchone()
            if row:
                if row["password_hash"] in ("!!", "", None):
                    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ? AND profile_id = ?", (pwd_hash, username, self.engine.active_profile_id))
            else:
                cursor.execute(
                    """INSERT INTO users (profile_id, username, password, uid, gid, gecos, home, shell, groups, password_hash, last_login) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.engine.active_profile_id, username, password, uid, gid, gecos, home, shell, groups, pwd_hash, "Jul 01 10:24:12")
                )
        self.engine.conn.commit()

        # Ensure /etc/passwd and /etc/shadow files are registered in the VFS table
        import stat
        if not self.engine.fs_mgr.exists("/etc"):
            try:
                self.engine.fs_mgr.mkdir("/etc", 0, 0, 4096, stat.S_IFDIR | 0o755)
            except Exception:
                pass
        if not self.engine.fs_mgr.exists("/etc/passwd"):
            try:
                self.engine.fs_mgr.mkfile("/etc/passwd", 0, 0, 0, stat.S_IFREG | 0o644)
            except Exception:
                pass
        if not self.engine.fs_mgr.exists("/etc/shadow"):
            try:
                self.engine.fs_mgr.mkfile("/etc/shadow", 0, 0, 0, stat.S_IFREG | 0o600)
            except Exception:
                pass

    def seed_last_logins(self):
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM last_logins WHERE profile_id = ?", (self.engine.active_profile_id,))
        if cursor.fetchone()[0] > 0:
            return

        now = time.time()
        logins = [
            ("root", "pts/0", "192.168.1.55", now - 86400 * 2, now - 86400 * 1.95),
            ("admin", "pts/1", "192.168.1.10", now - 3600 * 2, now - 3600 * 1.95),
        ]
        
        p_name = self.engine.persona_mgr.active_persona
        if p_name == "amrita":
            logins.append(("faculty", "pts/0", "192.168.1.12", now - 3600 * 5, now - 3600 * 4.5))
            logins.append(("student", "pts/1", "192.168.1.14", now - 3600 * 1, now - 3600 * 0.9))

        for user, tty, ip, lin, lout in logins:
            cursor.execute(
                """INSERT INTO last_logins (profile_id, username, tty, ip, login_time, logout_time) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, user, tty, ip, lin, lout)
            )
        self.engine.conn.commit()

    def get_user(self, username: str) -> dict | None:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND profile_id = ?", (username, self.engine.active_profile_id))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def list_users(self) -> list[dict]:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE profile_id = ?", (self.engine.active_profile_id,))
        return [dict(r) for r in cursor.fetchall()]

    def add_user(self, username: str, uid: int | None = None, gid: int | None = None, gecos: str = "", home: str | None = None, shell: str = "/bin/bash", groups: str = "") -> bool:
        if self.get_user(username):
            return False
            
        cursor = self.engine.conn.cursor()
        if uid is None:
            cursor.execute("SELECT MAX(uid) FROM users WHERE profile_id = ?", (self.engine.active_profile_id,))
            max_uid = cursor.fetchone()[0]
            uid = max(1000, max_uid + 1) if max_uid else 1000
        if gid is None:
            gid = uid
        if home is None:
            home = f"/home/{username}"
        if not groups:
            groups = username

        cursor.execute(
            """INSERT INTO users (profile_id, username, password, uid, gid, gecos, home, shell, groups, password_hash, last_login) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, username, "x", uid, gid, gecos, home, shell, groups, "!!", "")
        )
        self.engine.conn.commit()
        log.msg(f"Added user: {username} (UID: {uid}, GID: {gid}) for profile {self.engine.active_profile_id}")
        return True

    def delete_user(self, username: str) -> bool:
        if not self.get_user(username):
            return False
        cursor = self.engine.conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ? AND profile_id = ?", (username, self.engine.active_profile_id))
        self.engine.conn.commit()
        log.msg(f"Deleted user: {username} for profile {self.engine.active_profile_id}")
        return True

    def change_password(self, username: str, password_hash: str) -> bool:
        cursor = self.engine.conn.cursor()
        if self.get_user(username):
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ? AND profile_id = ?", (password_hash, username, self.engine.active_profile_id))
            self.engine.conn.commit()
            log.msg(f"Password updated for user: {username} for profile {self.engine.active_profile_id}")
            return True
        return False
