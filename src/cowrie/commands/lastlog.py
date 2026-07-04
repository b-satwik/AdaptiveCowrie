# lastlog command for Cowrie

import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_lastlog(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            self.write(f"root             pts/0    {self.protocol.clientIP}     {time.asctime(time.localtime(self.protocol.logintime))}\n")
            return

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        cursor = adaptive.conn.cursor()
        cursor.execute("SELECT username FROM users WHERE profile_id = ? ORDER BY uid ASC", (profile_id,))
        users = [r["username"] for r in cursor.fetchall()]

        self.write(f"{'Username':16s} {'Port':8s} {'From':16s} {'Latest'}\n")
        
        for u in users:
            cursor.execute("SELECT * FROM last_logins WHERE username = ? AND profile_id = ? ORDER BY login_time DESC LIMIT 1", (u, profile_id))
            row = cursor.fetchone()
            if row:
                tty = row["tty"]
                ip = row["ip"]
                lin = row["login_time"]
                time_str = time.strftime("%a %b %d %H:%M:%S +0000 %Y", time.localtime(lin))
                self.write(f"{u:16s} {tty:8s} {ip:16s} {time_str}\n")
            else:
                self.write(f"{u:16s} {'':8s} {'':16s} **Never logged in**\n")

commands["/usr/bin/lastlog"] = Command_lastlog
commands["lastlog"] = Command_lastlog
