# Adaptive Threat Score Manager for Cowrie

import time
from twisted.python import log

class ThreatScoreManager:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        pass

    def compute_threat_scores(self, profile_id: str) -> dict:
        cursor = self.engine.conn.cursor()
        
        # Retrieve all MITRE mappings for the profile
        cursor.execute(
            "SELECT command, technique, tactic, confidence FROM mitre_mappings WHERE profile_id = ?",
            (profile_id,)
        )
        rows = cursor.fetchall()

        recon_score = 0.0
        persistence_score = 0.0
        credential_access_score = 0.0
        privilege_escalation_score = 0.0
        discovery_score = 0.0
        impact_score = 0.0

        for row in rows:
            cmd = row["command"].strip().split()[0].split("/")[-1] if row["command"] else ""
            tactic = row["tactic"]
            conf = row["confidence"]

            if tactic == "Discovery":
                # Differentiate Recon from generic Discovery
                if cmd in ("whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ss", "route"):
                    recon_score += conf * 5.0
                else:
                    discovery_score += conf * 3.0
            elif tactic == "Persistence":
                persistence_score += conf * 8.0
            elif tactic == "Credential Access":
                credential_access_score += conf * 10.0
            elif tactic == "Privilege Escalation":
                privilege_escalation_score += conf * 7.0
            elif tactic == "Impact":
                impact_score += conf * 12.0

        # Include honeytoken interactions as a critical threat indicator
        # Retrieve honeytokens tripped for sessions in this profile
        cursor.execute(
            """SELECT SUM(honeytokens_tripped) FROM session_metrics 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?)""",
            (profile_id,)
        )
        val = cursor.fetchone()[0]
        honeytoken_tripped_count = val if val is not None else 0
        
        # Each honeytoken interaction adds 15 points
        overall_score = (
            recon_score + 
            persistence_score + 
            credential_access_score + 
            privilege_escalation_score + 
            discovery_score + 
            impact_score +
            (honeytoken_tripped_count * 15.0)
        )

        scores = {
            "recon": recon_score,
            "persistence": persistence_score,
            "credential_access": credential_access_score,
            "privilege_escalation": privilege_escalation_score,
            "discovery": discovery_score,
            "impact": impact_score,
            "overall": overall_score
        }

        # Update risk_score in profile_metadata
        cursor.execute(
            "UPDATE profile_metadata SET risk_score = ? WHERE profile_id = ?",
            (overall_score, profile_id)
        )
        self.engine.conn.commit()

        return scores
