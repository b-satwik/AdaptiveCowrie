# route command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_route(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            self.write("Kernel IP routing table\n")
            self.write("Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n")
            self.write("0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0\n")
            self.write("192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0\n")
            return

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        adaptive.active_profile_id = profile_id
        routes = adaptive.network_mgr.get_routes()
        self.write("Kernel IP routing table\n")
        self.write("Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n")
        for r in routes:
            self.write(f"{r['destination']:15s} {r['gateway']:15s} {r['genmask']:15s} {r['flags']:5s} {r['metric']:<6d} {r['ref']:<6d} {r['use']:<6d} {r['iface']}\n")

commands["route"] = Command_route
commands["/usr/sbin/route"] = Command_route
commands["/sbin/route"] = Command_route
