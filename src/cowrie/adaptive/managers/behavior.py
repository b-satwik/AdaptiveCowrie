# Adaptive Behavior Profiler for Cowrie

import time
import json
import random
from twisted.python import log

class AdaptiveBehaviorProfiler:
    def __init__(self, engine):
        self.engine = engine
        self.session_profiles = {}

    def start(self):
        pass

    def analyze_command(self, session_id: str, command: str, cwd: str, username: str = "root"):
        cursor = self.engine.conn.cursor()

        # Get profile_id for this session
        cursor.execute("SELECT profile_id FROM profile_sessions WHERE session_id = ?", (session_id,))
        p_row = cursor.fetchone()
        profile_id = p_row["profile_id"] if p_row else "default"

        # 1. Log to persistent bash_history table
        cursor.execute(
            """INSERT INTO bash_history (profile_id, username, session_id, command, timestamp, is_deleted) 
               VALUES (?, ?, ?, ?, ?, 0)""",
            (profile_id, username, session_id, command, time.time())
        )
        self.engine.conn.commit()

        # Initialize session profile
        if session_id not in self.session_profiles:
            self.session_profiles[session_id] = {
                "observed_tactics": set(),
                "commands_count": 0,
                "cumulative_risk": 0,
                "mitre_techniques": set(),
                "start_time": time.time(),
                "threat_phase": "Initial Access",
                "priv_esc_attempts": 0,
                "dirs_explored": set(),
                "files_created": set(),
                "files_modified": set()
            }
            # Initialize session_metrics row in DB
            cursor.execute(
                """INSERT OR IGNORE INTO session_metrics (session_id, start_time) 
                   VALUES (?, ?)""",
                (session_id, self.session_profiles[session_id]["start_time"])
            )
            self.engine.conn.commit()

        profile = self.session_profiles[session_id]
        profile["commands_count"] += 1

        # Track directory explorations
        profile["dirs_explored"].add(cwd)

        cmd_parts = command.strip().split()
        if not cmd_parts:
            return
            
        base_cmd = cmd_parts[0].split("/")[-1]

        tactic = None
        mitre_tag = ""
        risk = 1
        details = ""

        # Classifying based on base command
        if base_cmd in ("uname", "whoami", "id", "hostname", "hostnamectl", "df", "free", "uptime", "lsblk", "mount", "timedatectl"):
            tactic = "Discovery (System Info)"
            mitre_tag = "T1082" # System Information Discovery
            risk = 1
            details = f"System information discovery command: '{base_cmd}'"
        elif base_cmd in ("ifconfig", "ip", "netstat", "route", "ss", "arp"):
            tactic = "Discovery (Network)"
            mitre_tag = "T1049" # System Network Connections Discovery
            risk = 2
            details = f"Network discovery command: '{base_cmd}'"
        elif base_cmd in ("ps", "top"):
            tactic = "Discovery (Processes)"
            mitre_tag = "T1057" # Process Discovery
            risk = 2
            details = f"Process discovery command: '{base_cmd}'"
        elif base_cmd in ("sudo", "su"):
            tactic = "Privilege Escalation"
            mitre_tag = "T1548" # Abuse Elevation Control Mechanism
            risk = 3
            details = f"Elevation attempt command: '{command}'"
            profile["priv_esc_attempts"] += 1
        elif base_cmd in ("useradd", "adduser", "chpasswd", "passwd"):
            tactic = "Persistence"
            mitre_tag = "T1136" # Create Account
            risk = 4
            details = f"Account creation or password change: '{command}'"
        elif base_cmd in ("crontab", "at"):
            tactic = "Persistence"
            mitre_tag = "T1053" # Scheduled Task/Job
            risk = 3
            details = f"Persistence scheduling attempt: '{command}'"
        elif base_cmd in ("wget", "curl", "tftp", "ftp"):
            tactic = "Ingress Tool Transfer"
            mitre_tag = "T1105" # Ingress Tool Transfer
            risk = 4
            details = f"File download attempt: '{command}'"
        elif base_cmd in ("systemctl", "service"):
            tactic = "Discovery"
            mitre_tag = "T1007" # System Service Discovery
            risk = 2
            details = f"Simulated service interaction: '{command}'"
        elif base_cmd in ("touch", "mkdir", "echo") and (">" in command or ">>" in command):
            # Capture file creations/modifications
            for part in cmd_parts:
                if "/" in part and not part.startswith("-"):
                    profile["files_created"].add(part)
        elif base_cmd in ("rm", "mv", "sed", "truncate"):
            # Anti-forensics indicators
            tactic = "Defense Evasion"
            mitre_tag = "T1070" # Indicator Removal on Host
            risk = 3
            details = f"Anti-forensics log/file manipulation: '{command}'"

        profile["cumulative_risk"] += risk
        if mitre_tag:
            profile["mitre_techniques"].add(mitre_tag)
            profile["observed_tactics"].add(tactic)

        # Log behavior telemetry
        self.engine.telemetry_mgr.log_event(
            session_id=session_id,
            event_type="behavior_profiling",
            command=command,
            cwd=cwd,
            details=details or f"Command: '{base_cmd}' executed",
            mitre_tag=mitre_tag or "T1059 (Command and Scripting Interpreter)",
            risk_score=risk
        )

        # Active environment evolution
        self.update_threat_phase(session_id)

        # Update SQLite research metrics
        duration = time.time() - profile["start_time"]
        cursor.execute(
            """UPDATE session_metrics 
               SET duration = ?, commands_count = ?, dirs_explored = ?, files_created = ?, 
                   files_modified = ?, priv_esc_attempts = ?, risk_score_evolution = ?, mitre_attack_techniques = ?
               WHERE session_id = ?""",
            (
                duration,
                profile["commands_count"],
                json.dumps(list(profile["dirs_explored"])),
                json.dumps(list(profile["files_created"])),
                json.dumps(list(profile["files_modified"])),
                profile["priv_esc_attempts"],
                json.dumps([profile["cumulative_risk"]]),
                json.dumps(list(profile["mitre_techniques"])),
                session_id
            )
        )
        self.engine.conn.commit()

        # Get profile_id, src_ip, and ssh_client for this session to update features
        cursor.execute("SELECT profile_id, src_ip, ssh_client FROM profile_sessions WHERE session_id = ?", (session_id,))
        p_row = cursor.fetchone()
        if p_row:
            p_id = p_row["profile_id"]
            src_ip = p_row["src_ip"]
            client_banner = p_row["ssh_client"]
            
            # Map commands using MITREAttackManager
            if hasattr(self.engine, "mitre_mgr"):
                self.engine.mitre_mgr.map_command(session_id, command)
            
            # Recalculate threat scores using ThreatScoreManager
            if hasattr(self.engine, "threat_mgr"):
                self.engine.threat_mgr.compute_threat_scores(p_id)
            
            # Update behavioral features for the profile
            self.update_profile_features(p_id, session_id, src_ip, client_banner)

    def update_profile_features(self, profile_id: str, session_id: str, src_ip: str, client_banner: str):
        cursor = self.engine.conn.cursor()
        
        # 1. Fetch SSH key / fingerprint
        cursor.execute("SELECT fingerprint_hash FROM attacker_profiles WHERE profile_id = ?", (profile_id,))
        row = cursor.fetchone()
        ssh_key = row["fingerprint_hash"] if row else ""

        # 2. Fetch username
        cursor.execute("SELECT last_username FROM profile_metadata WHERE profile_id = ?", (profile_id,))
        row = cursor.fetchone()
        username = row["last_username"] if row else ""

        # 3. First N commands (N = 10)
        cursor.execute(
            """SELECT command FROM bash_history 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?) 
               ORDER BY timestamp ASC LIMIT 10""",
            (profile_id,)
        )
        first_n = [r["command"] for r in cursor.fetchall()]

        # 4. Command sequence similarity
        cursor.execute(
            """SELECT command FROM bash_history 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?) 
               ORDER BY timestamp ASC""",
            (profile_id,)
        )
        my_cmds = [r["command"] for r in cursor.fetchall()]

        # Fetch commands of all other profiles
        cursor.execute(
            """SELECT ps.profile_id, bh.command FROM bash_history bh
               JOIN profile_sessions ps ON bh.session_id = ps.session_id
               WHERE ps.profile_id != ?""",
            (profile_id,)
        )
        other_cmds_map = {}
        for r in cursor.fetchall():
            o_pid = r["profile_id"]
            if o_pid not in other_cmds_map:
                other_cmds_map[o_pid] = []
            other_cmds_map[o_pid].append(r["command"])

        # Calculate Jaccard similarity
        my_set = set(my_cmds)
        max_similarity = 0.0
        if my_set and other_cmds_map:
            for o_pid, o_cmds in other_cmds_map.items():
                o_set = set(o_cmds)
                if o_set:
                    intersect = len(my_set.intersection(o_set))
                    union = len(my_set.union(o_set))
                    sim = intersect / union if union > 0 else 0.0
                    if sim > max_similarity:
                        max_similarity = sim

        # 5. Fetch Threat Scores
        recon_score = 0.0
        persistence_score = 0.0
        credential_access_score = 0.0
        privilege_escalation_score = 0.0
        discovery_score = 0.0
        impact_score = 0.0

        # Compute scores directly from MITRE mappings
        cursor.execute(
            "SELECT command, tactic, confidence FROM mitre_mappings WHERE profile_id = ?",
            (profile_id,)
        )
        for r in cursor.fetchall():
            cmd = r["command"].strip().split()[0].split("/")[-1] if r["command"] else ""
            tactic = r["tactic"]
            conf = r["confidence"]
            if tactic == "Discovery":
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

        # 6. Honeytoken interactions
        cursor.execute(
            """SELECT SUM(honeytokens_tripped) FROM session_metrics 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?)""",
            (profile_id,)
        )
        val = cursor.fetchone()[0]
        honeytoken_tripped = val if val is not None else 0

        # 7. Filesystem traversal (unique dirs explored)
        cursor.execute(
            """SELECT dirs_explored FROM session_metrics 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?)""",
            (profile_id,)
        )
        unique_dirs = set()
        for r in cursor.fetchall():
            try:
                dirs = json.loads(r["dirs_explored"])
                unique_dirs.update(dirs)
            except Exception:
                pass
        filesystem_traversal = len(unique_dirs)

        # 8. Service modifications
        cursor.execute(
            """SELECT COUNT(*) FROM telemetry 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?) 
               AND (command LIKE '%systemctl%' OR command LIKE '%service%' OR event_type = 'service_modify')""",
            (profile_id,)
        )
        service_modifications = cursor.fetchone()[0]

        # 9. Uploads and Downloads
        cursor.execute(
            """SELECT COUNT(*) FROM telemetry 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?) 
               AND (command LIKE '%wget%' OR command LIKE '%curl%' OR command LIKE '%tftp%' OR command LIKE '%ftp%' OR event_type = 'upload')""",
            (profile_id,)
        )
        uploads = cursor.fetchone()[0]
        downloads = uploads

        # 10. Session metrics
        cursor.execute(
            """SELECT SUM(duration), SUM(commands_count) FROM session_metrics 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?)""",
            (profile_id,)
        )
        s_row = cursor.fetchone()
        session_duration = s_row[0] if s_row and s_row[0] is not None else 0.0
        commands_executed = s_row[1] if s_row and s_row[1] is not None else 0

        # 11. Failed commands
        cursor.execute(
            """SELECT COUNT(*) FROM telemetry 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ?) 
               AND event_type = 'command_failed'""",
            (profile_id,)
        )
        failed_commands = cursor.fetchone()[0]

        idle_time = max(0.0, session_duration - (commands_executed * 0.1))

        # 12. Memory (Previously created files/dirs revisited)
        cursor.execute(
            """SELECT files_created, dirs_explored FROM session_metrics 
               WHERE session_id IN (SELECT session_id FROM profile_sessions WHERE profile_id = ? AND session_id != ?)""",
            (profile_id, session_id)
        )
        past_files = set()
        past_dirs = set()
        for r in cursor.fetchall():
            try:
                past_files.update(json.loads(r["files_created"]))
                past_dirs.update(json.loads(r["dirs_explored"]))
            except Exception:
                pass
        
        created_files_revisited = 0
        created_dirs_revisited = 0
        installed_persistence_revisited = 0
        created_users_revisited = 0
        modified_services_revisited = 0

        for cmd in my_cmds:
            for pf in past_files:
                if pf and pf in cmd:
                    created_files_revisited += 1
            for pd in past_dirs:
                if pd and pd != "/" and pd in cmd:
                    created_dirs_revisited += 1
            if "cron" in cmd or "at" in cmd:
                installed_persistence_revisited += 1
            if "useradd" in cmd or "userdel" in cmd or "adduser" in cmd or "passwd" in cmd:
                created_users_revisited += 1
            if "systemctl" in cmd or "service" in cmd:
                modified_services_revisited += 1

        # 13. Insert or Replace behavior features row
        cursor.execute(
            """INSERT OR REPLACE INTO profile_behavior_features (
                profile_id, ssh_key, username, client_banner, src_ip,
                first_n_commands, command_sequence_similarity,
                recon_score, credential_access_score, privilege_escalation_score, persistence_score, discovery_score,
                honeytoken_interactions, filesystem_traversal, service_modifications, uploads, downloads,
                session_duration, commands_executed, failed_commands, idle_time,
                created_files_revisited, created_dirs_revisited, installed_persistence_revisited,
                created_users_revisited, modified_services_revisited
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )""",
            (
                profile_id, ssh_key, username, client_banner, src_ip,
                json.dumps(first_n), max_similarity,
                recon_score, credential_access_score, privilege_escalation_score, persistence_score, discovery_score,
                honeytoken_tripped, filesystem_traversal, service_modifications, uploads, downloads,
                session_duration, commands_executed, failed_commands, idle_time,
                created_files_revisited, created_dirs_revisited, installed_persistence_revisited,
                created_users_revisited, modified_services_revisited
            )
        )
        self.engine.conn.commit()

    def update_threat_phase(self, session_id: str):
        profile = self.session_profiles[session_id]
        score = profile["cumulative_risk"]
        old_phase = profile["threat_phase"]

        if score >= 35:
            new_phase = "Malware Operator"
        elif score >= 25:
            new_phase = "Privilege Escalation"
        elif score >= 15:
            new_phase = "Credential Hunter"
        elif score >= 5:
            new_phase = "Recon"
        else:
            new_phase = "Initial Access"

        if new_phase != old_phase:
            profile["threat_phase"] = new_phase
            log.msg(f"Session {session_id} threat phase escalated: {old_phase} -> {new_phase}")
            self.spawn_deceptions_for_phase(new_phase)

    def spawn_deceptions_for_phase(self, phase: str):
        """Active Deception: Dynamically spawn assets in VFS based on the threat phase."""
        fs = self.engine.fs_mgr
        log.msg(f"Active Deception Engine seeding assets for phase: {phase}...")

        # Save original active credentials
        orig_uid = getattr(fs, "active_uid", 0)
        orig_gid = getattr(fs, "active_gid", 0)
        orig_user = getattr(fs, "active_username", "root")

        # Temporarily act as root to spawn deception files
        fs.active_uid = 0
        fs.active_gid = 0
        fs.active_username = "root"

        try:
            if phase == "Recon":
                # Add files that encourage deeper recon
                if not fs.exists("/home/student/student_grades_2026.csv"):
                    fs.write_file_content("/home/student/student_grades_2026.csv", b"StudentId,Grade\n2026CSE003,B\n2026CSE004,A\n")
                if not fs.exists("/srv/lms/admissions_confidential.txt"):
                    fs.write_file_content("/srv/lms/admissions_confidential.txt", b"Amrita University admissions review data 2026.\n")

            elif phase == "Credential Hunter":
                # Add decoy credentials/ssh keys
                if not fs.exists("/home/research/.ssh"):
                    fs.mkdir("/home/research/.ssh", 1003, 1003, 4096, 16877)
                if not fs.exists("/home/research/.ssh/id_rsa"):
                    fs.write_file_content("/home/research/.ssh/id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\nb2BlcG9jaC1kZWNveS1rZXktbm90LXJlYWw15z8zP8=\n-----END OPENSSH PRIVATE KEY-----")
                    fs.update_metadata("/home/research/.ssh/id_rsa", uid=1003, gid=1003, mode=0o600)
                
                if not fs.exists("/home/faculty/api_keys.json"):
                    fs.write_file_content("/home/faculty/api_keys.json", b'{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", "github_token": "ghp_decoyToken12345678901234567890"}\n')

            elif phase == "Privilege Escalation":
                # Add readable sudo configurations or vulnerability hints
                if not fs.exists("/etc/sudoers.d"):
                    fs.mkdir("/etc/sudoers.d", 0, 0, 4096, 16877)
                if not fs.exists("/etc/sudoers.d/faculty"):
                    fs.write_file_content("/etc/sudoers.d/faculty", b"faculty ALL=(ALL:ALL) NOPASSWD: /usr/bin/systemctl restart nginx\n")

            elif phase == "Malware Operator":
                # Add crontabs pointing to persistence or mock processes
                if not fs.exists("/etc/cron.d"):
                    fs.mkdir("/etc/cron.d", 0, 0, 4096, 16877)
                if not fs.exists("/etc/cron.d/syscheck"):
                    fs.write_file_content("/etc/cron.d/syscheck", b"*/5 * * * * root /var/tmp/.syscheck >/dev/null 2>&1\n")
        finally:
            # Restore original active credentials
            fs.active_uid = orig_uid
            fs.active_gid = orig_gid
            fs.active_username = orig_user
