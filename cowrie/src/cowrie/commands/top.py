# Top command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_top(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        
        user = self.protocol.user.username
        procs = []
        if adaptive.enabled:
            profile_id = getattr(self.protocol.fs, "profile_id", "default")
            adaptive.active_profile_id = profile_id
            procs = adaptive.process_mgr.get_processes(session_user=user, session_cmd="top")
        else:
            # Fallback mock processes
            procs = [
                {"pid": 1, "user": "root", "cpu": 0.0, "mem": 0.1, "vsz": 22500, "rss": 1200, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:02", "command": "/sbin/init splash"},
                {"pid": 502, "user": "root", "cpu": 0.0, "mem": 0.4, "vsz": 78900, "rss": 5400, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:05", "command": "/usr/sbin/sshd -D"},
                {"pid": 4216, "user": user, "cpu": 0.0, "mem": 0.1, "vsz": 22000, "rss": 3500, "tty": "pts/0", "stat": "Ss", "start": "10:24", "time": "0:00", "command": "-bash"}
            ]

        self.write("top - 10:25:02 up  1:45,  1 user,  load average: 0.05, 0.03, 0.01\n")
        self.write(f"Tasks: {len(procs)} total,   1 running, {len(procs) - 1} sleeping,   0 stopped,   0 zombie\n")
        self.write("%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.6 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n")
        
        mem_kb = 8 * 1024 * 1024
        if adaptive.enabled:
            p_name = adaptive.persona_mgr.active_persona
            if p_name == "hospital":
                mem_kb = 16 * 1024 * 1024
            elif p_name == "startup":
                mem_kb = 4 * 1024 * 1024
            elif p_name == "cloud_provider":
                mem_kb = 32 * 1024 * 1024
                
        self.write(f"MiB Mem : {mem_kb/1024:.1f} total, {mem_kb*0.4/1024:.1f} free, {mem_kb*0.3/1024:.1f} used, {mem_kb*0.3/1024:.1f} buff/cache\n")
        self.write(f"MiB Swap:  2048.0 total,  2048.0 free,     0.0 used. {mem_kb*0.5/1024:.1f} avail Mem\n\n")
        
        self.write("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
        for p in procs:
            pid = str(p["pid"]).rjust(7)
            usr = p["user"].ljust(9)[:9]
            vsz = str(p["vsz"]).rjust(7)
            rss = str(p["rss"]).rjust(6)
            stat = p["stat"].ljust(1)
            cpu = f"{p['cpu']:.1f}".rjust(5)
            mem = f"{p['mem']:.1f}".rjust(5)
            time_str = p["time"].rjust(8)
            cmd = p["command"]
            self.write(f"{pid} {usr}  20   0 {vsz} {rss}      0 {stat}  {cpu}  {mem}   {time_str} {cmd}\n")

commands["/usr/bin/top"] = Command_top
commands["top"] = Command_top
commands["/bin/top"] = Command_top
