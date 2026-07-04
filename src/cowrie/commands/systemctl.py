# systemctl command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_systemctl(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        
        if not self.args or "list-units" in self.args:
            if adaptive.enabled:
                services = adaptive.service_mgr.list_services()
                self.write("  UNIT                                   LOAD   ACTIVE SUB     DESCRIPTION\n")
                for s in services:
                    status = "active" if s["status"] == "active" else "inactive"
                    sub = "running" if s["status"] == "active" else "dead"
                    name_str = f"{s['name']}.service".ljust(38)
                    self.write(f"  {name_str} loaded {status} {sub}   Simulated {s['name']} service\n")
                self.write("\nLOAD   = Reflects whether the unit definition was loaded into memory.\n")
                self.write("ACTIVE = The high-level unit activation state (local/parent).\n")
                self.write("SUB    = The low-level unit activation state of the unit.\n")
            return

        action = self.args[0]
        if action in ("start", "stop", "restart", "status") and len(self.args) >= 2:
            name = self.args[1]
            if name.endswith(".service"):
                name = name[:-8]
                
            if adaptive.enabled:
                if action == "start":
                    if not adaptive.service_mgr.start_service(name):
                        self.write(f"Failed to start {name}.service: Unit {name}.service not found.\n")
                elif action == "stop":
                    if not adaptive.service_mgr.stop_service(name):
                        self.write(f"Failed to stop {name}.service: Unit {name}.service not found.\n")
                elif action == "restart":
                    if not adaptive.service_mgr.restart_service(name):
                        self.write(f"Failed to restart {name}.service: Unit {name}.service not found.\n")
                elif action == "status":
                    svc = adaptive.service_mgr.get_service(name)
                    if svc:
                        active_str = "active (running)" if svc["status"] == "active" else "inactive (dead)"
                        self.write(f"● {name}.service - Simulated {name} service\n")
                        self.write(f"     Loaded: loaded\n")
                        self.write(f"     Active: {active_str}\n")
                        if svc["pid"]:
                            self.write(f"   Main PID: {svc['pid']}\n")
                    else:
                        self.write(f"Unit {name}.service could not be found.\n")
            return

commands["/bin/systemctl"] = Command_systemctl
commands["systemctl"] = Command_systemctl
commands["/usr/bin/systemctl"] = Command_systemctl
