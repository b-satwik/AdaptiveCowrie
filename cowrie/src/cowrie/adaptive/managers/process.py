# Adaptive Process Manager for Cowrie

import random

class AdaptiveProcessManager:
    def __init__(self, engine):
        self.engine = engine

    def get_processes(self, session_user="root", session_cmd="") -> list[dict]:
        # Base system processes present in almost all Linux installations
        procs = [
            {"pid": 1, "user": "root", "cpu": 0.0, "mem": 0.1, "vsz": 22500, "rss": 1200, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:02", "command": "/sbin/init splash"},
            {"pid": 2, "user": "root", "cpu": 0.0, "mem": 0.0, "vsz": 0, "rss": 0, "tty": "?", "stat": "S", "start": "Jun30", "time": "0:00", "command": "[kthreadd]"},
            {"pid": 3, "user": "root", "cpu": 0.0, "mem": 0.0, "vsz": 0, "rss": 0, "tty": "?", "stat": "I<", "start": "Jun30", "time": "0:00", "command": "[rcu_gp]"},
            {"pid": 4, "user": "root", "cpu": 0.0, "mem": 0.0, "vsz": 0, "rss": 0, "tty": "?", "stat": "I<", "start": "Jun30", "time": "0:00", "command": "[kworker/0:0H]"},
            {"pid": 120, "user": "root", "cpu": 0.0, "mem": 0.2, "vsz": 35600, "rss": 2800, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:01", "command": "/lib/systemd/systemd-udevd"},
            {"pid": 350, "user": "messagebus", "cpu": 0.0, "mem": 0.1, "vsz": 12400, "rss": 1800, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:00", "command": "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"},
            {"pid": 401, "user": "root", "cpu": 0.0, "mem": 0.1, "vsz": 32100, "rss": 2100, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:00", "command": "/usr/sbin/cron -f -P"},
            {"pid": 450, "user": "root", "cpu": 0.0, "mem": 0.3, "vsz": 54000, "rss": 3800, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:03", "command": "/lib/systemd/systemd-logind"},
            {"pid": 502, "user": "root", "cpu": 0.0, "mem": 0.4, "vsz": 78900, "rss": 5400, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:05", "command": "/usr/sbin/sshd -D"},
        ]

        # Add processes for active services dynamically
        services = self.engine.service_mgr.list_services()
        for svc in services:
            if svc["status"] == "active":
                name = svc["name"]
                pid = svc["pid"] or random.randint(1000, 3000)
                
                if name in ("nginx", "apache2"):
                    procs.append({"pid": pid, "user": "root", "cpu": 0.0, "mem": 0.5, "vsz": 140000, "rss": 8100, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:01", "command": f"/usr/sbin/{name} -g daemon on; master_process on;"})
                    procs.append({"pid": pid + 1, "user": "www-data", "cpu": 0.0, "mem": 0.3, "vsz": 142000, "rss": 4200, "tty": "?", "stat": "S", "start": "Jun30", "time": "0:00", "command": f"/usr/sbin/{name} -g daemon on; master_process on; worker_process"})
                elif name in ("mysql", "mariadb"):
                    procs.append({"pid": pid, "user": "mysql", "cpu": 0.1, "mem": 4.5, "vsz": 1230000, "rss": 92100, "tty": "?", "stat": "Ssl", "start": "Jun30", "time": "0:45", "command": "/usr/sbin/mysqld"})
                elif name in ("postgres", "postgresql"):
                    procs.append({"pid": pid, "user": "postgres", "cpu": 0.0, "mem": 1.2, "vsz": 320000, "rss": 24000, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:02", "command": "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main"})
                elif name in ("redis", "redis-server"):
                    procs.append({"pid": pid, "user": "redis", "cpu": 0.0, "mem": 0.8, "vsz": 89000, "rss": 12000, "tty": "?", "stat": "Ssl", "start": "Jun30", "time": "0:08", "command": "/usr/bin/redis-server 127.0.0.1:6379"})
                elif name == "docker":
                    procs.append({"pid": pid, "user": "root", "cpu": 0.1, "mem": 2.1, "vsz": 950000, "rss": 45000, "tty": "?", "stat": "Ssl", "start": "Jun30", "time": "0:25", "command": "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"})
                elif name == "fail2ban":
                    procs.append({"pid": pid, "user": "root", "cpu": 0.0, "mem": 0.4, "vsz": 115000, "rss": 14000, "tty": "?", "stat": "Ssl", "start": "Jun30", "time": "0:03", "command": "/usr/bin/python3 /usr/bin/fail2ban-server -xf start"})
                else:
                    procs.append({"pid": pid, "user": "root", "cpu": 0.0, "mem": 0.2, "vsz": 45000, "rss": 3500, "tty": "?", "stat": "Ss", "start": "Jun30", "time": "0:00", "command": f"/usr/sbin/{name}"})

        # Add the current session processes
        # Represent the ssh connection from client to server and the spawned bash shell
        procs.append({"pid": 4210, "user": "root", "cpu": 0.0, "mem": 0.3, "vsz": 105000, "rss": 6200, "tty": "?", "stat": "Ss", "start": "10:24", "time": "0:00", "command": f"sshd: {session_user} [priv]"})
        procs.append({"pid": 4215, "user": session_user, "cpu": 0.0, "mem": 0.2, "vsz": 105000, "rss": 4100, "tty": "pts/0", "stat": "Ss", "start": "10:24", "time": "0:00", "command": f"sshd: {session_user}@pts/0"})
        procs.append({"pid": 4216, "user": session_user, "cpu": 0.0, "mem": 0.1, "vsz": 22000, "rss": 3500, "tty": "pts/0", "stat": "Ss+", "start": "10:24", "time": "0:00", "command": "-bash"})
        
        # Append the currently executing command itself
        if session_cmd:
            procs.append({"pid": 4290, "user": session_user, "cpu": 0.0, "mem": 0.1, "vsz": 15000, "rss": 1800, "tty": "pts/0", "stat": "R+", "start": "10:25", "time": "0:00", "command": session_cmd})

        return procs
