# history command for Cowrie

import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_history(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if not adaptive.enabled:
            self.write("  1  history\n")
            return

        username = self.protocol.user.username
        session_id = str(self.protocol.sessionno)
        profile_id = getattr(self.protocol.fs, "profile_id", "default")
        cursor = adaptive.conn.cursor()

        # Handle history clear flag -c
        if len(self.args) > 0 and self.args[0] == "-c":
            # Mark history as deleted for this user session
            cursor.execute(
                "UPDATE bash_history SET is_deleted = 1 WHERE (username = ? OR session_id = ?) AND profile_id = ?",
                (username, session_id, profile_id)
            )
            adaptive.conn.commit()
            
            # Log the evasion attempt in telemetry
            adaptive.telemetry_mgr.log_event(
                session_id=session_id,
                event_type="defense_evasion_history_clear",
                command="history -c",
                details=f"User {username} cleared command history.",
                mitre_tag="T1070.003",
                risk_score=50
            )
            return

        # Fetch non-deleted history lines
        cursor.execute(
            "SELECT * FROM bash_history WHERE username = ? AND is_deleted = 0 AND profile_id = ? ORDER BY id ASC",
            (username, profile_id)
        )
        rows = cursor.fetchall()
        
        for idx, row in enumerate(rows, 1):
            self.write(f"  {idx:4d}  {row['command']}\n")

commands["history"] = Command_history
commands["/usr/bin/history"] = Command_history
