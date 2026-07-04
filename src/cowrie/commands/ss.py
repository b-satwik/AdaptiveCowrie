# ss command for Cowrie

import getopt
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_ss(HoneyPotCommand):
    def call(self) -> None:
        try:
            opts, args = getopt.getopt(self.args, "anlpt")
        except getopt.GetoptError:
            opts = []

        show_all = False
        show_listening = False
        show_processes = False

        for o, a in opts:
            if o == "-a":
                show_all = True
            elif o == "-l":
                show_listening = True
            elif o == "-p":
                show_processes = True

        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()

        if adaptive.enabled:
            profile_id = getattr(self.protocol.fs, "profile_id", "default")
            adaptive.active_profile_id = profile_id
            sockets = adaptive.network_mgr.get_sockets(self.protocol.clientIP, self.protocol.realClientPort)
        else:
            sockets = [
                {"proto": "tcp", "local_addr": "0.0.0.0:22", "remote_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 502, "program": "sshd"},
                {"proto": "tcp", "local_addr": f"192.168.1.105:22", "remote_addr": f"{self.protocol.clientIP}:{self.protocol.realClientPort}", "state": "ESTABLISHED", "pid": 4215, "program": "sshd: root@pts/0"}
            ]

        proc_header = " Process" if show_processes else ""
        self.write(f"Netid  State      Recv-Q Send-Q Local Address:Port       Peer Address:Port        {proc_header}\n")

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

            # Format addresses
            if ":" not in laddr:
                laddr += ":*"
            if ":" not in raddr:
                raddr += ":*"

            proc_str = f' users:(("{prog}",pid={pid},fd=3))' if show_processes and pid else ""
            self.write(f"{proto:<6s} {state:<10s} 0      0      {laddr:<25s} {raddr:<24s} {proc_str}\n")

commands["ss"] = Command_ss
commands["/usr/sbin/ss"] = Command_ss
commands["/sbin/ss"] = Command_ss
commands["/bin/ss"] = Command_ss
