# journalctl command for Cowrie

import getopt
import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_journalctl(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            self.write("-- No entries --\n")
            return

        # Parse options
        try:
            opts, args = getopt.getopt(self.args, "xeu:b", ["since=", "until="])
        except getopt.GetoptError as err:
            self.write(f"journalctl: {err}\n")
            return

        unit = None
        since = None
        until = None
        xe_mode = False

        for o, a in opts:
            if o == "-u":
                unit = a
                # Normalize unit name
                if not unit.endswith(".service") and not unit.endswith(".socket"):
                    unit += ".service"
            elif o in ("-x", "-e", "-xe"):
                xe_mode = True
            elif o == "--since":
                since = a
            elif o == "--until":
                until = a

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        cursor = adaptive.conn.cursor()
        query = "SELECT * FROM journal_logs WHERE is_deleted = 0 AND profile_id = ?"
        params = [profile_id]

        if unit:
            query += " AND (unit = ? OR syslog_identifier = ?)"
            params.extend([unit, unit.replace(".service", "")])
        
        query += " ORDER BY id ASC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        if not rows:
            self.write("-- No entries --\n")
            return

        hostname = adaptive.persona_mgr.hostname
        for r in rows:
            # Parse timestamp
            try:
                dt = time.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
                date_str = time.strftime("%b %e %H:%M:%S", dt)
            except Exception:
                date_str = "Jul 01 10:24:12"
            
            pid_str = f"[{r['pid']}]" if r["pid"] else ""
            self.write(f"{date_str} {hostname} {r['syslog_identifier']}{pid_str}: {r['message']}\n")

        if xe_mode:
            # Output typical journalctl trailing notice
            self.write(f"\n-- Support lines limit reached. Use -n to see more. --\n")

commands["/bin/journalctl"] = Command_journalctl
commands["journalctl"] = Command_journalctl
commands["/usr/bin/journalctl"] = Command_journalctl
commands["/sbin/journalctl"] = Command_journalctl
