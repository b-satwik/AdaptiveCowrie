# who, w, and users commands for Cowrie

import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_who(HoneyPotCommand):
    def call(self) -> None:
        cmd_name = self.environ.get("COMMAND_LINE", "who").split()[0].strip().split("/")[-1]
        
        # Get active sessions
        username = self.protocol.user.username
        client_ip = self.protocol.clientIP
        login_time = self.protocol.logintime
        
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()

        active_sessions = [{"user": username, "tty": "pts/0", "from": client_ip, "login": login_time}]
        
        # If Amrita persona is active, optionally spawn a mock concurrent session
        if adaptive.enabled and adaptive.persona_mgr.active_persona == "amrita":
            active_sessions.append({"user": "faculty", "tty": "pts/1", "from": "192.168.1.12", "login": login_time - 1800})

        if cmd_name == "users":
            users_list = [s["user"] for s in active_sessions]
            self.write(" ".join(users_list) + "\n")
            
        elif cmd_name == "w":
            # Print load averages and uptime
            now_str = time.strftime("%H:%M:%S")
            self.write(f" {now_str} up 2:45,  {len(active_sessions)} users,  load average: 0.05, 0.02, 0.01\n")
            self.write(f"{'USER':8s} {'TTY':8s} {'FROM':16s} {'LOGIN@':8s} {'IDLE':6s} {'JCPU':6s} {'PCPU':6s} {'WHAT'}\n")
            
            for s in active_sessions:
                login_str = time.strftime("%H:%M", time.localtime(s["login"]))
                what = "w" if s["user"] == username else "-bash"
                self.write(f"{s['user']:8s} {s['tty']:8s} {s['from']:16s} {login_str:8s} {'0.00s':6s} {'0.05s':6s} {'0.00s':6s} {what}\n")
                
        else: # who
            for s in active_sessions:
                time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["login"]))
                self.write(f"{s['user']:8s} {s['tty']:8s}         {time_str} ({s['from']})\n")

commands["who"] = Command_who
commands["/usr/bin/who"] = Command_who
commands["w"] = Command_who
commands["/usr/bin/w"] = Command_who
commands["users"] = Command_who
commands["/usr/bin/users"] = Command_who
