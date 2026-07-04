# Adaptive Telemetry Manager for Cowrie

import time
from twisted.python import log

class AdaptiveTelemetryManager:
    def __init__(self, engine):
        self.engine = engine

    def log_event(self, session_id: str, event_type: str, command: str, cwd: str, details: str, mitre_tag: str = "", risk_score: int = 1):
        cursor = self.engine.conn.cursor()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute(
            """INSERT INTO telemetry 
               (session_id, timestamp, event_type, command, cwd, details, mitre_tag, risk_score) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, t_str, event_type, command, cwd, details, mitre_tag, risk_score)
        )
        self.engine.conn.commit()

        # Emit to Cowrie standard logging pipeline (Twisted log)
        # This guarantees T-Pot's JSON log output plugin picks it up automatically!
        log.msg(
            eventid="cowrie.adaptive.telemetry",
            session=session_id,
            event_type=event_type,
            input=command,
            cwd=cwd,
            details=details,
            mitre_tag=mitre_tag,
            risk_score=risk_score,
            format="[ADAPTIVE TELEMETRY] %(event_type)s - %(details)s [Risk: %(risk_score)s, MITRE: %(mitre_tag)s]"
        )

    def get_session_telemetry(self, session_id: str) -> list[dict]:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM telemetry WHERE session_id = ? ORDER BY id ASC", (session_id,))
        return [dict(r) for r in cursor.fetchall()]

    def get_session_risk_score(self, session_id: str) -> int:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT SUM(risk_score) FROM telemetry WHERE session_id = ?", (session_id,))
        res = cursor.fetchone()[0]
        return res if res is not None else 0
