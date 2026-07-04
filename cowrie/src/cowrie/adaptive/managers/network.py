# Adaptive Network Manager for Cowrie

import random
from twisted.python import log

class AdaptiveNetworkManager:
    def __init__(self, engine):
        self.engine = engine
        self.dns_servers = ["1.1.1.1", "8.8.8.8"]

    def start(self):
        self.seed_network()

    def seed_network(self):
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM network_interfaces WHERE profile_id = ?", (self.engine.active_profile_id,))
        if cursor.fetchone()[0] > 0:
            return

        log.msg("Seeding persistent network configuration in SQLite...")
        
        # 1. Interfaces
        cursor.execute(
            """INSERT INTO network_interfaces (profile_id, name, ip, netmask, mac, rx_bytes, tx_bytes) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "eth0", "192.168.1.105", "255.255.255.0", "52:54:00:12:34:56", 1485292, 982142)
        )
        cursor.execute(
            """INSERT INTO network_interfaces (profile_id, name, ip, netmask, mac, rx_bytes, tx_bytes) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "lo", "127.0.0.1", "255.0.0.0", "00:00:00:00:00:00", 25641, 25641)
        )

        # 2. Routes
        cursor.execute(
            """INSERT INTO network_routes (profile_id, destination, gateway, genmask, flags, metric, ref, use, iface) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "0.0.0.0", "192.168.1.1", "0.0.0.0", "UG", 100, 0, 0, "eth0")
        )
        cursor.execute(
            """INSERT INTO network_routes (profile_id, destination, gateway, genmask, flags, metric, ref, use, iface) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "192.168.1.0", "0.0.0.0", "255.255.255.0", "U", 100, 0, 0, "eth0")
        )

        # 3. Sockets
        cursor.execute(
            """INSERT INTO network_sockets (profile_id, proto, local_addr, remote_addr, state, pid, program) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", 502, "sshd")
        )
        cursor.execute(
            """INSERT INTO network_sockets (profile_id, proto, local_addr, remote_addr, state, pid, program) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "tcp6", "[::]:22", "[::]:*", "LISTEN", 502, "sshd")
        )

        # Seed sockets for initial active services
        cursor.execute("SELECT * FROM system_services WHERE status = 'active' AND profile_id = ?", (self.engine.active_profile_id,))
        services = cursor.fetchall()
        for svc in services:
            self.open_service_sockets(svc["name"], svc["pid"])

        self.engine.conn.commit()

    def open_service_sockets(self, service_name: str, pid: int):
        cursor = self.engine.conn.cursor()
        pid = pid or random.randint(1000, 3000)
        
        # Mapping service names to common port configurations
        ports = []
        if service_name in ("nginx", "apache2"):
            ports = [("tcp", "0.0.0.0:80"), ("tcp", "0.0.0.0:443")]
        elif service_name in ("mysql", "mariadb"):
            ports = [("tcp", "127.0.0.1:3306")]
        elif service_name in ("postgres", "postgresql"):
            ports = [("tcp", "127.0.0.1:5432")]
        elif service_name in ("redis", "redis-server"):
            ports = [("tcp", "127.0.0.1:6379")]
            
        for proto, local_addr in ports:
            cursor.execute(
                """INSERT OR REPLACE INTO network_sockets (profile_id, proto, local_addr, remote_addr, state, pid, program) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, proto, local_addr, "0.0.0.0:*", "LISTEN", pid, service_name)
            )
        self.engine.conn.commit()

    def close_service_sockets(self, service_name: str):
        cursor = self.engine.conn.cursor()
        cursor.execute("DELETE FROM network_sockets WHERE program = ? AND profile_id = ?", (service_name, self.engine.active_profile_id))
        self.engine.conn.commit()

    def get_interfaces(self) -> list[dict]:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM network_interfaces WHERE profile_id = ?", (self.engine.active_profile_id,))
        return [dict(r) for r in cursor.fetchall()]

    def get_routes(self) -> list[dict]:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM network_routes WHERE profile_id = ?", (self.engine.active_profile_id,))
        return [dict(r) for r in cursor.fetchall()]

    def get_sockets(self, client_ip="192.168.1.55", client_port=54321) -> list[dict]:
        cursor = self.engine.conn.cursor()
        
        # Clean up any stale ESTABLISHED sockets first
        cursor.execute("DELETE FROM network_sockets WHERE state = 'ESTABLISHED' AND profile_id = ?", (self.engine.active_profile_id,))
        self.engine.conn.commit()

        # Insert active attacker connection
        cursor.execute("SELECT ip FROM network_interfaces WHERE name = 'eth0' AND profile_id = ?", (self.engine.active_profile_id,))
        row = cursor.fetchone()
        local_ip = row["ip"] if row else "192.168.1.105"

        cursor.execute(
            """INSERT INTO network_sockets (profile_id, proto, local_addr, remote_addr, state, pid, program) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (self.engine.active_profile_id, "tcp", f"{local_ip}:22", f"{client_ip}:{client_port}", "ESTABLISHED", 4215, "sshd: root@pts/0")
        )
        self.engine.conn.commit()

        cursor.execute("SELECT * FROM network_sockets WHERE profile_id = ?", (self.engine.active_profile_id,))
        return [dict(r) for r in cursor.fetchall()]
