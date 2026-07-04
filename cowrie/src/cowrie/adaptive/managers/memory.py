# Adaptive Memory Manager for Cowrie

import time
import uuid
import hashlib
from twisted.python import log
from cowrie.core.config import CowrieConfig

class MemoryLogObserver:
    def __init__(self, memory_mgr):
        self.memory_mgr = memory_mgr

    def __call__(self, event):
        try:
            if event.get("eventid") == "cowrie.log.closed":
                session_id = event.get("session")
                ttylog_path = event.get("ttylog")
                if session_id and ttylog_path:
                    self.memory_mgr.update_ttylog_path(session_id, ttylog_path)
        except Exception as e:
            log.msg(f"Error in MemoryLogObserver: {e}")

class AdaptiveMemoryManager:
    def __init__(self, engine):
        self.engine = engine
        self.enabled = CowrieConfig.getboolean("adaptive_memory", "enabled", fallback=True)
        self.retention_days = CowrieConfig.getint("adaptive_memory", "retention_days", fallback=7)
        self.minimum_confidence = CowrieConfig.getint("adaptive_memory", "minimum_confidence", fallback=80)
        self.log_observer = MemoryLogObserver(self)

    def start(self):
        if self.enabled:
            log.addObserver(self.log_observer)
            log.msg("Adaptive Memory Manager started and log observer registered.")

    def calculate_fingerprint_hash(self, ssh_key, username, client_banner, src_ip):
        data = f"{ssh_key or ''}:{username or ''}:{client_banner or ''}:{src_ip or ''}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def create_profile(self, fingerprint_hash=None, confidence=100.0, persona=None, first_seen=None, last_seen=None, expires_at=None):
        profile_id = str(uuid.uuid4())
        now = time.time()
        first_seen = first_seen or now
        last_seen = last_seen or now
        expires_at = expires_at or (now + (self.retention_days * 86400))
        persona = persona or getattr(self.engine.persona_mgr, "active_persona", "amrita")
        
        cursor = self.engine.conn.cursor()
        cursor.execute("""
            INSERT INTO attacker_profiles (profile_id, first_seen, last_seen, persona, fingerprint_hash, confidence, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (profile_id, first_seen, last_seen, persona, fingerprint_hash, confidence, expires_at))
        
        cursor.execute("""
            INSERT INTO profile_metadata (profile_id, last_username, last_hostname, risk_score, behavior_summary)
            VALUES (?, ?, ?, ?, ?)
        """, (profile_id, "", getattr(self.engine.persona_mgr, "hostname", "svr04"), 0.0, "New profile created."))
        
        self.engine.conn.commit()
        return profile_id

    def match_profile(self, session_id, username, src_ip, client_banner, ssh_key=None):
        if not self.enabled:
            return None, 0.0, False

        cursor = self.engine.conn.cursor()
        cursor.execute("""
            SELECT p.profile_id, p.fingerprint_hash, p.persona,
                   m.last_username,
                   (SELECT group_concat(src_ip) FROM profile_sessions WHERE profile_id = p.profile_id) as ips,
                   (SELECT group_concat(ssh_client) FROM profile_sessions WHERE profile_id = p.profile_id) as clients
            FROM attacker_profiles p
            LEFT JOIN profile_metadata m ON p.profile_id = m.profile_id
            WHERE p.expires_at > ?
        """, (time.time(),))
        rows = cursor.fetchall()

        best_profile_id = None
        best_score = 0.0

        for row in rows:
            candidate_id = row["profile_id"]
            cand_fingerprint = row["fingerprint_hash"]
            cand_username = row["last_username"]
            
            cand_ips = row["ips"].split(",") if row["ips"] else []
            cand_clients = row["clients"].split(",") if row["clients"] else []
            
            score = 0.0
            total_weight = 0.0
            
            # 1. SSH Public Key Match
            is_ssh_key_candidate = cand_fingerprint and (cand_fingerprint.startswith("SHA256:") or cand_fingerprint.startswith("ssh-") or ":" in cand_fingerprint)
            if ssh_key or is_ssh_key_candidate:
                total_weight += 50.0
                if ssh_key and cand_fingerprint == ssh_key:
                    score += 50.0
            
            # 2. Username Match
            total_weight += 15.0
            if username == cand_username:
                score += 15.0
                
            # 3. Client Banner Match
            if client_banner or cand_clients:
                total_weight += 15.0
                if client_banner in cand_clients:
                    score += 15.0
                    
            # 4. Source IP Match
            if src_ip or cand_ips:
                total_weight += 15.0
                if src_ip in cand_ips:
                    score += 15.0
                    
            # 5 & 6. Command sequence / timing matching
            total_weight += 10.0
            if src_ip in cand_ips and username == cand_username:
                score += 10.0
            elif username == cand_username:
                score += 5.0
                
            confidence = (score / total_weight) * 100.0 if total_weight > 0 else 0.0
            if confidence > best_score:
                best_score = confidence
                best_profile_id = candidate_id

        if best_profile_id and best_score >= self.minimum_confidence:
            profile_id = best_profile_id
            confidence = best_score
            is_new = False
            self.update_last_seen(profile_id)
            self.save_profile(profile_id, last_username=username)
        else:
            fp_hash = ssh_key if ssh_key else self.calculate_fingerprint_hash(ssh_key, username, client_banner, src_ip)
            profile_id = self.create_profile(fingerprint_hash=fp_hash, confidence=100.0)
            self.save_profile(profile_id, last_username=username)
            confidence = 100.0
            is_new = True

        # Phase 1: debug prints
        if is_new:
            print("Created New Profile")
            print(f"Profile ID: {profile_id}")
            print(f"Confidence: {confidence:.2f}")
            log.msg(f"Profile Created: {profile_id}")
        else:
            print("Matched Profile")
            print("Existing Profile")
            print(f"Profile ID: {profile_id}")
            print(f"Confidence: {confidence:.2f}")
            log.msg(f"Profile Matched: {profile_id}")

        return profile_id, confidence, is_new

    def link_session(self, session_id, profile_id, src_ip, ssh_client):
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM profile_sessions WHERE session_id = ?", (session_id,))
        if cursor.fetchone()[0] > 0:
            return
        
        cursor.execute("""
            INSERT INTO profile_sessions (session_id, profile_id, ttylog_path, login_time, logout_time, src_ip, ssh_client)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (session_id, profile_id, "", time.time(), 0.0, src_ip, ssh_client))
        self.engine.conn.commit()
        log.msg(f"Session Linked: {session_id} to profile {profile_id}")

    def link_logout(self, session_id):
        cursor = self.engine.conn.cursor()
        cursor.execute("""
            UPDATE profile_sessions
            SET logout_time = ?
            WHERE session_id = ?
        """, (time.time(), session_id))
        self.engine.conn.commit()

    def update_last_seen(self, profile_id, last_seen_time=None):
        last_seen_time = last_seen_time or time.time()
        expires_at = last_seen_time + (self.retention_days * 86400)
        cursor = self.engine.conn.cursor()
        cursor.execute("""
            UPDATE attacker_profiles
            SET last_seen = ?, expires_at = ?
            WHERE profile_id = ?
        """, (last_seen_time, expires_at, profile_id))
        self.engine.conn.commit()

    def save_profile(self, profile_id, **kwargs):
        cursor = self.engine.conn.cursor()
        ap_cols = ["first_seen", "last_seen", "persona", "fingerprint_hash", "confidence", "expires_at"]
        pm_cols = ["last_username", "last_hostname", "risk_score", "behavior_summary"]
        
        for k, v in kwargs.items():
            if k in ap_cols:
                cursor.execute(f"UPDATE attacker_profiles SET {k} = ? WHERE profile_id = ?", (v, profile_id))
            elif k in pm_cols:
                cursor.execute(f"UPDATE profile_metadata SET {k} = ? WHERE profile_id = ?", (v, profile_id))
        self.engine.conn.commit()

    def restore_profile(self, profile_id):
        # Phase 1 only
        pass

    def expire_profiles(self):
        now = time.time()
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT profile_id FROM attacker_profiles WHERE expires_at < ?", (now,))
        expired_ids = [row[0] for row in cursor.fetchall()]
        for p_id in expired_ids:
            self.delete_profile(p_id)
            log.msg(f"Profile Expired: {p_id}")

    def delete_profile(self, profile_id):
        cursor = self.engine.conn.cursor()
        cursor.execute("DELETE FROM attacker_profiles WHERE profile_id = ?", (profile_id,))
        cursor.execute("DELETE FROM profile_metadata WHERE profile_id = ?", (profile_id,))
        cursor.execute("DELETE FROM profile_sessions WHERE profile_id = ?", (profile_id,))
        self.engine.conn.commit()

    def list_profiles(self):
        cursor = self.engine.conn.cursor()
        cursor.execute("""
            SELECT p.profile_id, p.first_seen, p.last_seen, p.persona, p.fingerprint_hash, p.confidence, p.expires_at,
                   m.last_username, m.last_hostname, m.risk_score, m.behavior_summary
            FROM attacker_profiles p
            LEFT JOIN profile_metadata m ON p.profile_id = m.profile_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def update_ttylog_path(self, session_id, ttylog_path):
        cursor = self.engine.conn.cursor()
        cursor.execute("""
            UPDATE profile_sessions
            SET ttylog_path = ?
            WHERE session_id = ?
        """, (ttylog_path, session_id))
        self.engine.conn.commit()
