# Adaptive Persona Manager for Cowrie

import os
import stat
import time
import random
from twisted.python import log
from cowrie.core.config import CowrieConfig

PERSONAS = {
    "amrita": {
        "hostname": "amrita-research01",
        "users": [
            {"username": "admin", "uid": 1001, "gid": 1001, "home": "/home/admin", "shell": "/bin/bash", "groups": "admin,sudo,wheel"},
            {"username": "faculty", "uid": 1002, "gid": 1002, "home": "/home/faculty", "shell": "/bin/bash", "groups": "faculty,shared"},
            {"username": "research", "uid": 1003, "gid": 1003, "home": "/home/research", "shell": "/bin/bash", "groups": "research,shared"},
            {"username": "student", "uid": 1004, "gid": 1004, "home": "/home/student", "shell": "/bin/sh", "groups": "student"},
            {"username": "placement", "uid": 1005, "gid": 1005, "home": "/home/placement", "shell": "/bin/bash", "groups": "placement,shared"},
            {"username": "backup", "uid": 1006, "gid": 1006, "home": "/home/backup", "shell": "/bin/sh", "groups": "backup"},
            {"username": "www-data", "uid": 33, "gid": 33, "home": "/var/www", "shell": "/usr/sbin/nologin", "groups": "www-data"},
            {"username": "mysql", "uid": 111, "gid": 111, "home": "/var/lib/mysql", "shell": "/usr/sbin/nologin", "groups": "mysql"},
            {"username": "postgres", "uid": 112, "gid": 112, "home": "/var/lib/postgresql", "shell": "/usr/sbin/nologin", "groups": "postgres"},
            {"username": "docker", "uid": 113, "gid": 113, "home": "/var/lib/docker", "shell": "/usr/sbin/nologin", "groups": "docker"},
        ],
        "services": ["nginx", "apache2", "mysql", "postgresql", "docker", "cron", "openssh", "fail2ban", "redis"],
        "directories": [
            "/srv/lms",
            "/var/www/amrita",
            "/home/faculty",
            "/home/student",
            "/home/research",
            "/home/projects/student-portal",
            "/home/projects/attendance-api",
            "/home/projects/erp-backend",
            "/home/projects/cyber-lab",
            "/home/admin"
        ],
        "files": {
            "/srv/lms/attendance_2026.xlsx": b"[Excel Spreadsheet: Amrita University Student Attendance Log for Jan-June 2026]",
            "/srv/lms/exam_schedule.pdf": b"%PDF-1.4\n% Amrita University Semester Exam Time Table - 2026\n",
            "/var/www/amrita/index.html": b"<html><body><h1>Welcome to Amrita Vishwa Vidyapeetham Intranet</h1></body></html>\n",
            "/home/faculty/faculty_contacts.xlsx": b"[Excel Spreadsheet: Faculty Directories and Personal Contact Numbers]",
            "/home/student/semester_results.csv": b"StudentId,Name,Subject,Grade\n2026CSE001,Aditya,CyberSecurity,A+\n2026CSE002,Deepa,Cryptography,A\n",
            "/home/research/research_grants.pdf": b"%PDF-1.4\n% DRDO & ISRO Funded Research Grants & Proposals - Amrita Cyber Security Department\n",
            "/home/admin/placement_drive.xlsx": b"[Excel Spreadsheet: Company Recruitment Schedules & Student Eligible List 2026]",
            "/home/admin/hostel_students.xlsx": b"[Excel Spreadsheet: Hostel Allocations & Mess Card Details]",
            "/home/admin/fees_2026.xlsx": b"[Excel Spreadsheet: Fee Receipts, Arrears and Scholarship Details]",
            "/home/projects/student-portal/.git/config": b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@github.com:amrita-edu/student-portal.git\n",
            "/home/projects/attendance-api/.git/config": b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@github.com:amrita-edu/attendance-api.git\n",
            "/home/projects/erp-backend/.git/config": b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@github.com:amrita-edu/erp-backend.git\n",
            "/home/projects/cyber-lab/.git/config": b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@github.com:amrita-edu/cyber-lab.git\n",
        }
    },
    "university": {
        "hostname": "edu-research-node01",
        "users": [
            {"username": "professor", "uid": 1001, "gid": 1001, "home": "/home/professor", "shell": "/bin/bash", "groups": "professor,faculty,shared"},
            {"username": "gradstudent", "uid": 1002, "gid": 1002, "home": "/home/gradstudent", "shell": "/bin/bash", "groups": "gradstudent,shared"},
            {"username": "registrar", "uid": 1003, "gid": 1003, "home": "/home/registrar", "shell": "/bin/sh", "groups": "registrar,staff"},
        ],
        "services": ["apache2", "postgresql", "cron"],
        "directories": [
            "/home/professor/research",
            "/home/gradstudent/thesis",
            "/home/shared/syllabus",
            "/opt/slurm",
            "/var/www/html/portal"
        ],
        "files": {
            "/home/professor/research/quantum_simulation.py": b"# Quantum Computing Simulation\nimport numpy as np\nprint('Initializing qubit simulation...')\n",
            "/home/gradstudent/thesis/notes.txt": b"TODO: fix slurm cluster script before submitting the job next Monday.\n",
            "/home/shared/syllabus/cs101.txt": b"CS101: Introduction to Programming\nRoom: Hall A\nTime: Tue/Thu 10:00 AM\n",
            "/etc/apache2/sites-available/default.conf": b"<VirtualHost *:80>\n\tDocumentRoot /var/www/html/portal\n\tServerName portal.university.edu\n</VirtualHost>\n",
            "/var/www/html/portal/index.html": b"<html><body><h1>University Portal Login</h1></body></html>\n"
        }
    },
    "manufacturing": {
        "hostname": "scada-plc-hmi",
        "users": [
            {"username": "operator", "uid": 1010, "gid": 1010, "home": "/home/operator", "shell": "/bin/sh", "groups": "operator,scada"},
            {"username": "engineer", "uid": 1011, "gid": 1011, "home": "/home/engineer", "shell": "/bin/bash", "groups": "engineer,scada,admin"},
            {"username": "ot-admin", "uid": 1012, "gid": 1012, "home": "/home/ot-admin", "shell": "/bin/bash", "groups": "ot-admin,admin"},
        ],
        "services": ["nginx", "redis-server", "fail2ban", "cron"],
        "directories": [
            "/opt/scada/plc_config",
            "/home/engineer/backups",
            "/etc/nginx/conf.d",
            "/var/log/nginx"
        ],
        "files": {
            "/opt/scada/plc_config/modbus_map.json": b"{\n  'coils': [0, 1, 2, 3],\n  'holding_registers': [40001, 40002],\n  'baud_rate': 9600\n}\n",
            "/home/engineer/backups/plc_backup_2026.cfg": b"# PLC Controller Backup Config\nDEVICE_ID=PLC_UNIT_04\nIP_ADDR=192.168.10.45\nPORT=502\n",
            "/etc/nginx/nginx.conf": b"user nginx;\nworker_processes auto;\nerror_log /var/log/nginx/error.log;\nhttp {\n  include /etc/nginx/mime.types;\n}\n"
        }
    },
    "hospital": {
        "hostname": "emr-portal-db",
        "users": [
            {"username": "doctor", "uid": 1020, "gid": 1020, "home": "/home/doctor", "shell": "/bin/bash", "groups": "doctor,medical"},
            {"username": "nurse", "uid": 1021, "gid": 1021, "home": "/home/nurse", "shell": "/bin/sh", "groups": "nurse,medical"},
            {"username": "ehr-admin", "uid": 1022, "gid": 1022, "home": "/home/ehr-admin", "shell": "/bin/bash", "groups": "ehr-admin,admin"},
        ],
        "services": ["nginx", "mysql", "cron"],
        "directories": [
            "/var/db/records",
            "/home/doctor/schedules",
            "/etc/mysql/conf.d"
        ],
        "files": {
            "/var/db/records/patients_schema.sql": b"CREATE TABLE patients (\n  id INT PRIMARY KEY,\n  first_name VARCHAR(50),\n  last_name VARCHAR(50),\n  ssn VARCHAR(11),\n  diagnosis TEXT\n);\n",
            "/home/doctor/schedules/shift_rotations.csv": b"Doctor,Shift,Date\nDr. Smith,Night,2026-07-02\nDr. Jones,Day,2026-07-02\n",
            "/etc/mysql/my.cnf": b"[mysqld]\nuser = mysql\npid-file = /var/run/mysqld/mysqld.pid\nsocket = /var/run/mysqld/mysqld.sock\nport = 3306\n"
        }
    },
    "government": {
        "hostname": "gov-secure-node",
        "users": [
            {"username": "agent", "uid": 1030, "gid": 1030, "home": "/home/agent", "shell": "/bin/bash", "groups": "agent,clearance_l1"},
            {"username": "sysops", "uid": 1031, "gid": 1031, "home": "/home/sysops", "shell": "/bin/bash", "groups": "sysops,admin,clearance_l2"},
        ],
        "services": ["apache2", "postgres", "cron", "fail2ban"],
        "directories": [
            "/var/log/audit",
            "/home/agent/briefs",
            "/etc/postgresql/14/main"
        ],
        "files": {
            "/etc/postgresql/14/main/pg_hba.conf": b"# PostgreSQL Client Authentication Configuration File\nlocal   all             all                                     peer\nhost    all             all             127.0.0.1/32            md5\n",
            "/home/agent/briefs/operational_summary.txt": b"OPERATION NEST: Infrastructure security audit on schedule. No leaks detected.\n",
            "/etc/ssh/sshd_config": b"Port 22\nPermitRootLogin no\nPasswordAuthentication yes\nChallengeResponseAuthentication no\nUsePAM yes\n"
        }
    },
    "startup": {
        "hostname": "nest-dev-server",
        "users": [
            {"username": "developer", "uid": 1040, "gid": 1040, "home": "/home/developer", "shell": "/bin/bash", "groups": "developer,devops,shared"},
            {"username": "designer", "uid": 1041, "gid": 1041, "home": "/home/designer", "shell": "/bin/sh", "groups": "designer,shared"},
            {"username": "founder", "uid": 1042, "gid": 1042, "home": "/home/founder", "shell": "/bin/bash", "groups": "founder,admin"},
        ],
        "services": ["docker", "jenkins", "redis", "nginx"],
        "directories": [
            "/opt/projects/frontend",
            "/opt/projects/backend",
            "/home/developer/keys",
            "/etc/docker"
        ],
        "files": {
            "/opt/projects/frontend/package.json": b"{\n  'name': 'startup-frontend',\n  'version': '1.0.0',\n  'scripts': {\n    'start': 'next start'\n  }\n}\n",
            "/etc/docker/daemon.json": b"{\n  'log-driver': 'json-file',\n  'log-opts': {\n    'max-size': '10m'\n  }\n}\n",
            "/home/developer/keys/id_ed25519.pub": b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7sY28pZ3/8bQdYmZ8y2+815z8zP8= developer@startup\n"
        }
    },
    "cloud_provider": {
        "hostname": "k8s-node-worker02",
        "users": [
            {"username": "ec2-user", "uid": 1000, "gid": 1000, "home": "/home/ec2-user", "shell": "/bin/bash", "groups": "ec2-user,wheel,docker"},
            {"username": "cloud-operator", "uid": 1050, "gid": 1050, "home": "/home/cloud-operator", "shell": "/bin/bash", "groups": "cloud-operator,docker"},
        ],
        "services": ["docker", "nginx", "gitlab-runner"],
        "directories": [
            "/etc/kubernetes",
            "/var/lib/docker",
            "/etc/gitlab-runner"
        ],
        "files": {
            "/etc/gitlab-runner/config.toml": b"concurrent = 4\ncheck_interval = 0\n[session_server]\n  session_timeout = 1800\n",
            "/etc/kubernetes/kubelet.conf": b"apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n"
        }
    }
}

class AdaptivePersonaManager:
    def __init__(self, engine):
        self.engine = engine
        self.active_persona = None
        self.hostname = "ubuntu"

    def start(self):
        p_name = CowrieConfig.get("adaptive", "persona", fallback="random").strip().lower()
        if p_name == "random" or p_name not in PERSONAS:
            p_name = random.choice(list(PERSONAS.keys()))
        
        self.active_persona = p_name
        self.hostname = PERSONAS[p_name]["hostname"]
        
        log.msg(f"Active deception persona initialized: {self.active_persona} (hostname: {self.hostname})")

        if not CowrieConfig.has_section("honeypot"):
            CowrieConfig.add_section("honeypot")
        CowrieConfig.set("honeypot", "hostname", self.hostname)

        self.setup_persona_in_db()

    def setup_persona_in_db(self):
        self.engine.fs_mgr.active_profile_id = self.engine.active_profile_id
        if self.engine.fs_mgr.exists("/etc/persona_initialized"):
            return

        log.msg(f"Setting up persona '{self.active_persona}' directories, files, users, and services in SQLite VFS...")
        p_info = PERSONAS[self.active_persona]

        # 1. Create directories
        for directory in p_info["directories"]:
            if not self.engine.fs_mgr.exists(directory):
                parts = directory.strip("/").split("/")
                curr_path = ""
                for part in parts:
                    curr_path += "/" + part
                    if not self.engine.fs_mgr.exists(curr_path):
                        self.engine.fs_mgr.mkdir(curr_path, 0, 0, 4096, 16877)

        # 2. Create files
        for file_path, content in p_info["files"].items():
            parent_dir = os.path.dirname(file_path)
            if not self.engine.fs_mgr.exists(parent_dir):
                parts = parent_dir.strip("/").split("/")
                curr_path = ""
                for part in parts:
                    curr_path += "/" + part
                    if not self.engine.fs_mgr.exists(curr_path):
                        self.engine.fs_mgr.mkdir(curr_path, 0, 0, 4096, 16877)
            
            self.engine.fs_mgr.write_file_content(file_path, content)

        # 3. Create Users & Groups
        import hashlib
        salt = "salt123"
        
        def get_default_password(username: str) -> str:
            parts = username.split("-")
            return "-".join(p.capitalize() for p in parts) + "@2026"

        cursor = self.engine.conn.cursor()
        for user in p_info["users"]:
            username = user["username"]
            shell = user["shell"]
            pwd_hash = "!!"
            is_system_locked = username in (
                "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", 
                "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", 
                "systemd-network", "systemd-resolve", "messagebus", "sshd", "mysql", 
                "postgres", "docker"
            ) or shell.endswith("/usr/sbin/nologin") or shell.endswith("/bin/sync")
            
            if not is_system_locked:
                password = get_default_password(username)
                pwd_hash = hashlib.sha512((password + salt).encode()).hexdigest()

            # Insert or Update
            cursor.execute("SELECT password_hash FROM users WHERE username = ? AND profile_id = ?", (username, self.engine.active_profile_id))
            row = cursor.fetchone()
            if row:
                if row["password_hash"] in ("!!", "", None):
                    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ? AND profile_id = ?", (pwd_hash, username, self.engine.active_profile_id))
            else:
                cursor.execute(
                    """INSERT INTO users 
                       (profile_id, username, uid, gid, home, shell, groups, password_hash, last_login) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.engine.active_profile_id, username, user["uid"], user["gid"], user["home"], user["shell"], user["groups"], pwd_hash, "Jul 01 10:24:12")
                )
            if not self.engine.fs_mgr.exists(user["home"]):
                self.engine.fs_mgr.mkdir(user["home"], user["uid"], user["gid"], 4096, 16877)
            else:
                self.engine.fs_mgr.update_metadata(user["home"], uid=user["uid"], gid=user["gid"], mode=16877)
                
            # Seed .ssh/authorized_keys for ssh-capable users
            if user["username"] in ("admin", "faculty", "research", "professor", "engineer", "sysops", "developer", "founder", "ec2-user"):
                ssh_dir = f"{user['home']}/.ssh"
                if not self.engine.fs_mgr.exists(ssh_dir):
                    self.engine.fs_mgr.mkdir(ssh_dir, user["uid"], user["gid"], 4096, 16877)
                    self.engine.fs_mgr.update_metadata(ssh_dir, mode=stat.S_IFDIR | 0o700)
                else:
                    self.engine.fs_mgr.update_metadata(ssh_dir, uid=user["uid"], gid=user["gid"], mode=stat.S_IFDIR | 0o700)
                auth_keys = f"{ssh_dir}/authorized_keys"
                if not self.engine.fs_mgr.exists(auth_keys):
                    key_content = f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3e1{user['username']}fakekey... {user['username']}@company.internal\n"
                    self.engine.fs_mgr.write_file_content(auth_keys, key_content.encode())
                    self.engine.fs_mgr.update_metadata(auth_keys, uid=user["uid"], gid=user["gid"], mode=stat.S_IFREG | 0o600)
                else:
                    self.engine.fs_mgr.update_metadata(auth_keys, uid=user["uid"], gid=user["gid"], mode=stat.S_IFREG | 0o600)

        # 4. Initialize services status in SQL
        for service in p_info["services"]:
            pid = random.randint(1000, 3000)
            uptime = random.randint(10000, 500000)
            cursor.execute(
                """INSERT OR REPLACE INTO system_services (profile_id, name, status, pid, uptime) 
                   VALUES (?, ?, ?, ?, ?)""",
                (self.engine.active_profile_id, service, "active", pid, uptime)
            )

        self.engine.conn.commit()

        # Write the marker file to VFS
        self.engine.fs_mgr.write_file_content("/etc/persona_initialized", b"1\n")
        log.msg(f"Persona '{self.active_persona}' successfully initialized and persistent.")
