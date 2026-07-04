# dmesg command for Cowrie

import getopt
import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_dmesg(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            self.write("[    0.000000] Linux version 5.15.0-88-generic (buildd@lcy02-amd64-013) (gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04) )\n")
            return

        try:
            opts, args = getopt.getopt(self.args, "T")
        except getopt.GetoptError:
            opts = []

        human_readable = False
        for o, a in opts:
            if o == "-T":
                human_readable = True

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        cursor = adaptive.conn.cursor()
        cursor.execute("SELECT * FROM kernel_logs WHERE profile_id = ? ORDER BY id ASC", (profile_id,))
        rows = cursor.fetchall()

        now = time.time()
        for r in rows:
            uptime = r["uptime_sec"]
            message = r["message"]
            
            if human_readable:
                # Convert uptime offset to a mock system date-time
                log_time = now - 3600 + uptime
                time_str = time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(log_time))
                self.write(f"[{time_str}] {message}\n")
            else:
                self.write(f"[{uptime:12.6f}] {message}\n")

commands["/bin/dmesg"] = Command_dmesg
commands["dmesg"] = Command_dmesg
commands["/usr/bin/dmesg"] = Command_dmesg
