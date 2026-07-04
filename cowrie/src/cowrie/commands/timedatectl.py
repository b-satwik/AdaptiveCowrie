# timedatectl command for Cowrie

import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_timedatectl(HoneyPotCommand):
    def call(self) -> None:
        t_str = time.strftime("%a %Y-%m-%d %H:%M:%S %Z")
        self.write(f"               Local time: {t_str}\n")
        self.write(f"           Universal time: {t_str}\n")
        self.write(f"                 RTC time: {time.strftime('%a %Y-%m-%d %H:%M:%S')}\n")
        self.write("                Time zone: Etc/UTC (UTC, +0000)\n")
        self.write("System clock synchronized: yes\n")
        self.write("              NTP service: active\n")
        self.write("          RTC in local TZ: no\n")

commands["/bin/timedatectl"] = Command_timedatectl
commands["timedatectl"] = Command_timedatectl
commands["/usr/bin/timedatectl"] = Command_timedatectl
