# Adaptive Honeytoken Manager for Cowrie

import stat
from twisted.python import log

HONEYTOKENS = {
    "/home/professor/research/quantum_simulation.py": {"type": "Research Data", "risk": 7},
    "/home/engineer/backups/plc_backup_2026.cfg": {"type": "SCADA Configuration Backup", "risk": 9},
    "/var/db/records/patients_schema.sql": {"type": "EMR Database Schema", "risk": 8},
    "/home/agent/briefs/operational_summary.txt": {"type": "Classified Intelligence Briefing", "risk": 9},
    "/home/developer/aws_credentials.json": {"type": "AWS API Access Keys", "risk": 10},
    "/home/developer/keys/id_ed25519.pub": {"type": "Developer Private Key Backup", "risk": 9},
    "/etc/gitlab-runner/config.toml": {"type": "CI/CD Pipeline Configurations", "risk": 8}
}

class AdaptiveHoneytokenManager:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        # Dynamically seed honeytoken files that might not be in persona definitions
        p_name = self.engine.persona_mgr.active_persona
        if p_name == "startup":
            if not self.engine.fs_mgr.exists("/home/developer/aws_credentials.json"):
                self.engine.fs_mgr.write_file_content(
                    "/home/developer/aws_credentials.json",
                    b"{\n  'default': {\n    'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',\n    'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n  }\n}\n"
                )

    def check_interaction(self, session_id: str, path: str, cwd: str) -> bool:
        resolved_path = self.engine.fs_mgr.resolve_path(path, cwd)
        if resolved_path in HONEYTOKENS:
            token = HONEYTOKENS[resolved_path]
            # Log high-severity alert using TelemetryManager
            self.engine.telemetry_mgr.log_event(
                session_id=session_id,
                event_type="honeytoken_access",
                command=f"cat {path}" if "cat" not in resolved_path else resolved_path,
                cwd=cwd,
                details=f"ATTACKER ACCESS TO HONEYTOKEN: Type='{token['type']}', Path='{resolved_path}'",
                mitre_tag="T1083 (File and Directory Discovery) / T1552 (Unsecured Credentials)",
                risk_score=token["risk"]
            )
            log.msg(f"[SECURITY ALERT] Attacker accessed honeytoken '{resolved_path}' of type '{token['type']}'!")
            return True
        return False
