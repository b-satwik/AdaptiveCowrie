# last command for Cowrie

import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_last(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        
        # Track attacker's active session first
        username = self.protocol.user.username
        client_ip = self.protocol.clientIP
        login_time = self.protocol.logintime

        if not adaptive.enabled:
            # Fallback output
            self.write(
                "{:8s} {:12s} {:16s} {}   still logged in\n\n".format(
                    username, "pts/0", client_ip,
                    time.strftime("%a %b %d %H:%M", time.localtime(login_time))
                )
            )
            self.write(f"wtmp begins {time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(login_time - 86400))}\n")
            return

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        cursor = adaptive.conn.cursor()
        
        # Retrieve persistent logons
        cursor.execute("SELECT * FROM last_logins WHERE profile_id = ? ORDER BY login_time DESC", (profile_id,))
        rows = cursor.fetchall()

        for r in rows:
            user = r["username"]
            tty = r["tty"]
            ip = r["ip"]
            lin = r["login_time"]
            lout = r["logout_time"]

            lin_str = time.strftime("%a %b %d %H:%M", time.localtime(lin))
            if lout:
                duration_min = int((lout - lin) / 60)
                dur_h = duration_min // 60
                dur_m = duration_min % 60
                lout_str = time.strftime("%H:%M", time.localtime(lout))
                status_str = f"- {lout_str}  ({dur_h:02d}:{dur_m:02d})"
            else:
                status_str = "  still logged in"

            self.write(f"{user:8s} {tty:12s} {ip:16s} {lin_str} {status_str}\n")

        self.write("\n")
        cursor.execute("SELECT min(login_time) FROM last_logins WHERE profile_id = ?", (profile_id,))
        min_time = cursor.fetchone()[0] or (login_time - 86400 * 3)
        self.write(f"wtmp begins {time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(min_time))}\n")

commands["/usr/bin/last"] = Command_last
commands["last"] = Command_last
