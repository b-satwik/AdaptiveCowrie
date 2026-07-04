# ip command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.write("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
            return

        obj = self.args[0]
        cmd = self.args[1] if len(self.args) > 1 else "show"
        
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            # Fallback output
            self.write_fallback(obj, cmd)
            return

        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        # Temporarily ensure active_profile_id matches the session before list/get call
        adaptive.active_profile_id = profile_id

        net_mgr = adaptive.network_mgr
        interfaces = net_mgr.get_interfaces()
        routes = net_mgr.get_routes()

        if obj in ("addr", "address", "a"):
            for idx, i in enumerate(interfaces, 1):
                name = i["name"]
                ip = i["ip"]
                mac = i["mac"]
                mask = i["netmask"]
                
                # Convert mask to cidr prefix length
                parts = mask.split(".")
                cidr = sum(bin(int(x)).count("1") for x in parts)

                if name == "lo":
                    self.write(f"{idx}: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n")
                    self.write(f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
                    self.write(f"    inet 127.0.0.1/8 scope host lo\n")
                    self.write(f"       valid_lft forever preferred_lft forever\n")
                else:
                    self.write(f"{idx}: {name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n")
                    self.write(f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n")
                    self.write(f"    inet {ip}/{cidr} brd 192.168.1.255 scope global dynamic {name}\n")
                    self.write(f"       valid_lft 86120sec preferred_lft 86120sec\n")

        elif obj in ("link", "l"):
            for idx, i in enumerate(interfaces, 1):
                name = i["name"]
                mac = i["mac"]
                if name == "lo":
                    self.write(f"{idx}: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n")
                    self.write(f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
                else:
                    self.write(f"{idx}: {name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n")
                    self.write(f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n")

        elif obj in ("route", "r"):
            for r in routes:
                dest = r["destination"]
                gateway = r["gateway"]
                iface = r["iface"]
                metric = r["metric"]
                
                # Fetch interface IP
                cursor = adaptive.conn.cursor()
                cursor.execute("SELECT ip FROM network_interfaces WHERE name = ? AND profile_id = ?", (iface, profile_id))
                row = cursor.fetchone()
                ip = row["ip"] if row else "192.168.1.105"

                if dest == "0.0.0.0":
                    self.write(f"default via {gateway} dev {iface} proto dhcp src {ip} metric {metric} \n")
                else:
                    # Form subnet/cidr block
                    parts = r["genmask"].split(".")
                    cidr = sum(bin(int(x)).count("1") for x in parts)
                    self.write(f"{dest}/{cidr} dev {iface} proto kernel scope link src {ip} metric {metric} \n")

        elif obj in ("neigh", "n", "neighbor"):
            self.write("192.168.1.1 dev eth0 lladdr 52:54:00:12:34:01 REACHABLE\n")
        else:
            self.write(f"Object '{obj}' not supported.\n")

    def write_fallback(self, obj: str, cmd: str) -> None:
        if obj in ("addr", "address", "a"):
            self.write("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n")
            self.write("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
            self.write("    inet 127.0.0.1/8 scope host lo\n")
            self.write("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\n")
            self.write("    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n")
            self.write(f"    inet 192.168.1.105/24 brd 192.168.1.255 scope global eth0\n")
        elif obj in ("route", "r"):
            self.write("default via 192.168.1.1 dev eth0\n")
            self.write("192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.105\n")
        else:
            self.write("\n")

commands["ip"] = Command_ip
commands["/usr/sbin/ip"] = Command_ip
commands["/sbin/ip"] = Command_ip
commands["/bin/ip"] = Command_ip
