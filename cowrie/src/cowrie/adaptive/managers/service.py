# Adaptive Service Manager for Cowrie

import random
from twisted.python import log

class AdaptiveServiceManager:
    def __init__(self, engine):
        self.engine = engine

    def get_service(self, name: str) -> dict | None:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM system_services WHERE name = ? AND profile_id = ?", (name, self.engine.active_profile_id))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def list_services(self) -> list[dict]:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM system_services WHERE profile_id = ?", (self.engine.active_profile_id,))
        return [dict(r) for r in cursor.fetchall()]

    def start_service(self, name: str) -> bool:
        cursor = self.engine.conn.cursor()
        svc = self.get_service(name)
        if svc:
            pid = random.randint(1000, 3000)
            cursor.execute("UPDATE system_services SET status = 'active', pid = ?, uptime = 0 WHERE name = ? AND profile_id = ?", (pid, name, self.engine.active_profile_id))
            self.engine.conn.commit()
            log.msg(f"Service '{name}' started (PID: {pid}) for profile {self.engine.active_profile_id}.")
            
            # Sync listening sockets
            self.engine.network_mgr.open_service_sockets(name, pid)

            # Log system events
            self.engine.log_mgr.add_system_log("/var/log/syslog", "syslog", f"systemd[1]: Started {name} service.")
            if name in ("nginx", "apache2"):
                self.engine.log_mgr.add_system_log(f"/var/log/{name}/error.log", name, f"2026/07/01 10:25:01 [notice] {pid}#{pid}: start worker processes")
            return True
        return False

    def stop_service(self, name: str) -> bool:
        cursor = self.engine.conn.cursor()
        svc = self.get_service(name)
        if svc:
            cursor.execute("UPDATE system_services SET status = 'inactive', pid = NULL, uptime = NULL WHERE name = ? AND profile_id = ?", (name, self.engine.active_profile_id))
            self.engine.conn.commit()
            log.msg(f"Service '{name}' stopped for profile {self.engine.active_profile_id}.")
            
            # Sync listening sockets
            self.engine.network_mgr.close_service_sockets(name)

            self.engine.log_mgr.add_system_log("/var/log/syslog", "syslog", f"systemd[1]: Stopped {name} service.")
            return True
        return False

    def restart_service(self, name: str) -> bool:
        self.stop_service(name)
        return self.start_service(name)
