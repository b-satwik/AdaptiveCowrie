# Adaptive MITRE ATT&CK Manager for Cowrie

import time
from twisted.python import log

# Predefined command-to-technique mapping dictionary allowing multiple techniques per command.
MITRE_COMMAND_MAPPINGS = {
    "uname": [
        {"technique": "T1082", "tactic": "Discovery", "confidence": 1.0, "details": "System Information Discovery"}
    ],
    "whoami": [
        {"technique": "T1033", "tactic": "Discovery", "confidence": 1.0, "details": "System Owner/User Discovery"}
    ],
    "id": [
        {"technique": "T1033", "tactic": "Discovery", "confidence": 1.0, "details": "System Owner/User Discovery"}
    ],
    "hostname": [
        {"technique": "T1082", "tactic": "Discovery", "confidence": 1.0, "details": "System Information Discovery"}
    ],
    "ifconfig": [
        {"technique": "T1016", "tactic": "Discovery", "confidence": 1.0, "details": "System Network Configuration Discovery"}
    ],
    "ip": [
        {"technique": "T1016", "tactic": "Discovery", "confidence": 1.0, "details": "System Network Configuration Discovery"}
    ],
    "netstat": [
        {"technique": "T1049", "tactic": "Discovery", "confidence": 1.0, "details": "System Network Connections Discovery"}
    ],
    "ss": [
        {"technique": "T1049", "tactic": "Discovery", "confidence": 1.0, "details": "System Network Connections Discovery"}
    ],
    "route": [
        {"technique": "T1049", "tactic": "Discovery", "confidence": 1.0, "details": "System Network Connections Discovery"}
    ],
    "ps": [
        {"technique": "T1057", "tactic": "Discovery", "confidence": 1.0, "details": "Process Discovery"}
    ],
    "top": [
        {"technique": "T1057", "tactic": "Discovery", "confidence": 1.0, "details": "Process Discovery"}
    ],
    "sudo": [
        {"technique": "T1548.001", "tactic": "Privilege Escalation", "confidence": 0.9, "details": "Abuse Elevation Control Mechanism: Setuid and Setgid"},
        {"technique": "T1078", "tactic": "Defense Evasion", "confidence": 0.7, "details": "Valid Accounts"}
    ],
    "su": [
        {"technique": "T1548.001", "tactic": "Privilege Escalation", "confidence": 0.9, "details": "Abuse Elevation Control Mechanism: Setuid and Setgid"},
        {"technique": "T1078", "tactic": "Defense Evasion", "confidence": 0.7, "details": "Valid Accounts"}
    ],
    "useradd": [
        {"technique": "T1136.001", "tactic": "Persistence", "confidence": 1.0, "details": "Create Account: Local Account"}
    ],
    "adduser": [
        {"technique": "T1136.001", "tactic": "Persistence", "confidence": 1.0, "details": "Create Account: Local Account"}
    ],
    "passwd": [
        {"technique": "T1098", "tactic": "Persistence", "confidence": 0.8, "details": "Account Manipulation"},
        {"technique": "T1003", "tactic": "Credential Access", "confidence": 0.6, "details": "OS Credential Dumping"}
    ],
    "chpasswd": [
        {"technique": "T1098", "tactic": "Persistence", "confidence": 0.8, "details": "Account Manipulation"},
        {"technique": "T1003", "tactic": "Credential Access", "confidence": 0.6, "details": "OS Credential Dumping"}
    ],
    "crontab": [
        {"technique": "T1053.003", "tactic": "Persistence", "confidence": 1.0, "details": "Scheduled Task/Job: Cron"},
        {"technique": "T1053.003", "tactic": "Privilege Escalation", "confidence": 1.0, "details": "Scheduled Task/Job: Cron"}
    ],
    "at": [
        {"technique": "T1053.003", "tactic": "Persistence", "confidence": 1.0, "details": "Scheduled Task/Job: Cron"}
    ],
    "wget": [
        {"technique": "T1105", "tactic": "Command and Control", "confidence": 0.9, "details": "Ingress Tool Transfer"},
        {"technique": "T1059.004", "tactic": "Execution", "confidence": 0.5, "details": "Command and Scripting Interpreter: Unix Shell"}
    ],
    "curl": [
        {"technique": "T1105", "tactic": "Command and Control", "confidence": 0.9, "details": "Ingress Tool Transfer"},
        {"technique": "T1059.004", "tactic": "Execution", "confidence": 0.5, "details": "Command and Scripting Interpreter: Unix Shell"}
    ],
    "rm": [
        {"technique": "T1070.004", "tactic": "Defense Evasion", "confidence": 0.8, "details": "Indicator Removal: File Deletion"}
    ],
    "mv": [
        {"technique": "T1070.004", "tactic": "Defense Evasion", "confidence": 0.6, "details": "Indicator Removal: File Deletion"}
    ],
    "sed": [
        {"technique": "T1070.004", "tactic": "Defense Evasion", "confidence": 0.5, "details": "Indicator Removal: File Deletion"}
    ],
    "iptables": [
        {"technique": "T1562.004", "tactic": "Defense Evasion", "confidence": 1.0, "details": "Impair Defenses: Disable or Modify System Firewall"}
    ],
    "shutdown": [
        {"technique": "T1529", "tactic": "Impact", "confidence": 1.0, "details": "System Shutdown/Reboot"}
    ],
    "reboot": [
        {"technique": "T1529", "tactic": "Impact", "confidence": 1.0, "details": "System Shutdown/Reboot"}
    ],
    "poweroff": [
        {"technique": "T1529", "tactic": "Impact", "confidence": 1.0, "details": "System Shutdown/Reboot"}
    ],
    "init": [
        {"technique": "T1529", "tactic": "Impact", "confidence": 0.8, "details": "System Shutdown/Reboot"}
    ]
}

class MITREAttackManager:
    def __init__(self, engine):
        self.engine = engine

    def start(self):
        pass

    def map_command(self, session_id: str, command: str) -> list[dict]:
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return []
        
        base_cmd = cmd_parts[0].split("/")[-1]
        
        # Get profile_id linked to session
        profile_id = None
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT profile_id FROM profile_sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()
        if row:
            profile_id = row["profile_id"]

        mappings = MITRE_COMMAND_MAPPINGS.get(base_cmd, [])
        
        # If no mapping, default to generic Unix shell execution
        if not mappings:
            mappings = [{"technique": "T1059.004", "tactic": "Execution", "confidence": 0.5, "details": "Command and Scripting Interpreter: Unix Shell"}]

        # Allow multiple techniques per command
        for mapping in mappings:
            cursor.execute(
                """INSERT INTO mitre_mappings 
                   (session_id, profile_id, command, technique, tactic, confidence, timestamp) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session_id, profile_id, command, mapping["technique"], mapping["tactic"], mapping["confidence"], time.time())
            )
        self.engine.conn.commit()
        return mappings
