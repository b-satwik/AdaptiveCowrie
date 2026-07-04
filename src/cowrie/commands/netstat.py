# netstat command for Cowrie

import getopt
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_netstat(HoneyPotCommand):
    def show_version(self) -> None:
        self.write("net-tools 1.60\nnetstat 1.42 (2001-04-15)\n")

    def show_help(self) -> None:
        self.write("Usage: netstat [-vWnNcaeol] [-p] [-r] [-i]\n")

    def call(self) -> None:
        try:
            opts, args = getopt.getopt(self.args, "anlprtuvVhp")
        except getopt.GetoptError:
            opts = []

        show_all = False
        show_listening = False
        show_programs = False

        for o, a in opts:
            if o == "-a":
                show_all = True
            elif o == "-l":
                show_listening = True
            elif o == "-p":
                show_programs = True
            elif o == "-V":
                self.show_version()
                return
            elif o == "-h":
                self.show_help()
                return

        # If neither -a nor -l is specified, show established connections
        if not show_all and not show_listening:
            show_all = False # Just connections

        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        
        # Get sockets
        if adaptive.enabled:
            profile_id = getattr(self.protocol.fs, "profile_id", "default")
            adaptive.active_profile_id = profile_id
            sockets = adaptive.network_mgr.get_sockets(self.protocol.clientIP, self.protocol.realClientPort)
        else:
            sockets = [
                {"proto": "tcp", "local_addr": "0.0.0.0:22", "remote_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 502, "program": "sshd"},
                {"proto": "tcp", "local_addr": f"192.168.1.105:22", "remote_addr": f"{self.protocol.clientIP}:{self.protocol.realClientPort}", "state": "ESTABLISHED", "pid": 4215, "program": "sshd: root@pts/0"}
            ]

        self.write("Active Internet connections (servers and established)\n")
        pid_header = " PID/Program name    " if show_programs else ""
        self.write(f"Proto Recv-Q Send-Q Local Address           Foreign Address         State       {pid_header}\n")

        for s in sockets:
            proto = s["proto"]
            laddr = s["local_addr"]
            raddr = s["remote_addr"]
            state = s["state"]
            pid = s["pid"]
            prog = s["program"]

            is_listen = (state == "LISTEN")
            if is_listen and not (show_listening or show_all):
                continue
            if not is_listen and show_listening:
                continue

            prog_str = f" {pid}/{prog}" if show_programs and pid else ""
            self.write(f"{proto:5s}      0      0 {laddr:23s} {raddr:23s} {state:11s} {prog_str}\n")

commands["/bin/netstat"] = Command_netstat
commands["netstat"] = Command_netstat
