# Unit tests for Adaptive Deception Engine

import unittest
import os
import sqlite3
from unittest.mock import MagicMock, patch

from cowrie.core.config import CowrieConfig
from cowrie.adaptive.engine import AdaptiveEngine

class TestAdaptiveDeception(unittest.TestCase):
    def setUp(self) -> None:
        # Patch config values for tests
        if not CowrieConfig.has_section("adaptive"):
            CowrieConfig.add_section("adaptive")
        CowrieConfig.set("adaptive", "enabled", "true")
        CowrieConfig.set("adaptive", "database", ":memory:")
        CowrieConfig.set("adaptive", "persona", "startup")

        if not CowrieConfig.has_section("shell"):
            CowrieConfig.add_section("shell")
        if not CowrieConfig.has_section("honeypot"):
            CowrieConfig.add_section("honeypot")

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        CowrieConfig.set("shell", "processes", os.path.join(base_dir, "src", "cowrie", "data", "cmdoutput.json"))
        CowrieConfig.set("shell", "filesystem", os.path.join(base_dir, "src", "cowrie", "data", "fs.pickle"))
        CowrieConfig.set("honeypot", "contents_path", os.path.join(base_dir, "honeyfs"))
        
        # Reset the Singleton instance of AdaptiveEngine to force re-initialization
        AdaptiveEngine._instance = None
        self.engine = AdaptiveEngine.get_instance()
        self.engine.fs_mgr.start("linux-x64-lsb", "/root")
        self.engine.persona_mgr.start()
        self.engine.log_mgr.start()
        self.engine.honeytoken_mgr.start()
        self.engine.network_mgr.start()
        self.engine.user_mgr.start()
        self.engine.behavior_profiler.start()

    def tearDown(self) -> None:
        self.engine.conn.close()
        AdaptiveEngine._instance = None

    def test_engine_init(self) -> None:
        self.assertTrue(self.engine.enabled)
        self.assertIsNotNone(self.engine.conn)
        self.assertEqual(self.engine.persona_mgr.active_persona, "startup")
        self.assertEqual(self.engine.persona_mgr.hostname, "nest-dev-server")

    def test_vfs_persistence(self) -> None:
        fs = self.engine.fs_mgr
        # Verify file creation
        fs.mkfile("/tmp/test_file.txt", 0, 0, 10, 33188)
        self.assertTrue(fs.exists("/tmp/test_file.txt"))
        
        # Verify write and read file content
        fs.write_file_content("/tmp/test_file.txt", b"hello world")
        self.assertEqual(fs.file_contents("/tmp/test_file.txt"), b"hello world")
        
        # Verify directory creation
        fs.mkdir("/tmp/test_dir", 0, 0, 4096, 16877)
        self.assertTrue(fs.isdir("/tmp/test_dir"))
        self.assertIn("test_dir", fs.listdir("/tmp"))

        # Verify removal
        fs.remove("/tmp/test_file.txt")
        self.assertFalse(fs.exists("/tmp/test_file.txt"))

    def test_services(self) -> None:
        svc = self.engine.service_mgr
        # Check defaults
        services = svc.list_services()
        self.assertTrue(any(s["name"] == "nginx" for s in services))
        
        # Check start/stop service
        svc.stop_service("nginx")
        self.assertEqual(svc.get_service("nginx")["status"], "inactive")
        svc.start_service("nginx")
        self.assertEqual(svc.get_service("nginx")["status"], "active")

    def test_processes(self) -> None:
        proc_mgr = self.engine.process_mgr
        procs = proc_mgr.get_processes(session_user="root", session_cmd="ps aux")
        # Ensure nginx processes are present since nginx is active
        cmd_lines = [p["command"] for p in procs]
        self.assertTrue(any("nginx" in cmd for cmd in cmd_lines))

    def test_network(self) -> None:
        net_mgr = self.engine.network_mgr
        sockets = net_mgr.get_sockets(client_ip="192.168.1.55", client_port=54321)
        # Verify listening on port 22 and 80
        self.assertTrue(any(s["local_addr"] == "0.0.0.0:22" for s in sockets))
        self.assertTrue(any(s["local_addr"] == "0.0.0.0:80" for s in sockets))
        self.assertTrue(any(s["state"] == "ESTABLISHED" for s in sockets))

    def test_honeytokens_and_telemetry(self) -> None:
        # Trigger honeytoken access
        fs = self.engine.fs_mgr
        fs.sessionno = 9999
        content = fs.file_contents("/home/developer/aws_credentials.json")
        self.assertIn(b"AKIAIOSFODNN7EXAMPLE", content)
        
        # Check telemetry
        events = self.engine.telemetry_mgr.get_session_telemetry("9999")
        self.assertTrue(any(e["event_type"] == "honeytoken_access" for e in events))
        score = self.engine.telemetry_mgr.get_session_risk_score("9999")
        self.assertEqual(score, 10)

    def test_root_operations_commands(self) -> None:
        from cowrie.shell.protocol import HoneyPotInteractiveProtocol
        from cowrie.test.fake_server import FakeServer
        from cowrie.test.fake_transport import FakeTransport
        from cowrie.test.fake_server import FakeAvatar
        
        proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        
        # Ensure we are in root / first
        proto.cwd = "/"
        
        # Test pwd
        tr.clear()
        proto.lineReceived(b"pwd\n")
        self.assertIn(b"/\n", tr.value())
        
        # Test ls /
        tr.clear()
        proto.lineReceived(b"ls /\n")
        self.assertNotIn(b"No such file or directory", tr.value())
        self.assertIn(b"home", tr.value())
        
        # Test ls (while cwd is /)
        tr.clear()
        proto.lineReceived(b"ls\n")
        self.assertNotIn(b"No such file or directory", tr.value())
        self.assertIn(b"home", tr.value())
        
        # Test touch /file
        tr.clear()
        proto.lineReceived(b"touch /file\n")
        self.assertTrue(self.engine.fs_mgr.exists("/file"))
        
        # Test mkdir /dir
        tr.clear()
        proto.lineReceived(b"mkdir /dir\n")
        self.assertTrue(self.engine.fs_mgr.exists("/dir"))
        self.assertTrue(self.engine.fs_mgr.isdir("/dir"))
        
        # Test cd /
        proto.cwd = "/home"
        tr.clear()
        proto.lineReceived(b"cd /\n")
        self.assertEqual(proto.cwd, "/")
        
        proto.connectionLost()

    def test_permissions_enforcement(self) -> None:
        fs = self.engine.fs_mgr
        import stat
        
        # 1. Create admin-owned dir and file with 700 / 600 permissions
        fs.mkdir("/home/admin", 1001, 1001, 4096, stat.S_IFDIR | 0o700)
        fs.mkfile("/home/admin/secret.txt", 1001, 1001, 10, stat.S_IFREG | 0o600)
        fs.write_file_content("/home/admin/secret.txt", b"secret info")
        
        # 2. Access as root (UID 0) - should succeed
        fs.active_uid = 0
        fs.active_gid = 0
        fs.active_username = "root"
        self.assertTrue(fs.exists("/home/admin/secret.txt"))
        self.assertEqual(fs.file_contents("/home/admin/secret.txt"), b"secret info")
        
        # 3. Access as admin (UID 1001) - should succeed
        fs.active_uid = 1001
        fs.active_gid = 1001
        fs.active_username = "admin"
        self.assertTrue(fs.exists("/home/admin/secret.txt"))
        self.assertEqual(fs.file_contents("/home/admin/secret.txt"), b"secret info")
        
        # 4. Access as student (UID 1004) - should fail with PermissionDenied
        fs.active_uid = 1004
        fs.active_gid = 1004
        fs.active_username = "student"
        
        from cowrie.shell.fs import PermissionDenied
        with self.assertRaises(PermissionDenied):
            fs.file_contents("/home/admin/secret.txt")
            
        with self.assertRaises(PermissionDenied):
            fs.mkfile("/home/admin/hack.txt", 1004, 1004, 5, stat.S_IFREG | 0o644)

    def test_etc_group_and_last(self) -> None:
        fs = self.engine.fs_mgr
        
        # Access group file as root
        fs.active_uid = 0
        fs.active_gid = 0
        fs.active_username = "root"
        
        group_content = fs.file_contents("/etc/group").decode()
        self.assertIn("root:x:0:", group_content)
        self.assertIn("admin:x:", group_content)

    def test_session_init_with_dynamic_user(self) -> None:
        # Test CowrieServer initialization to ensure users table gets seeded
        from cowrie.shell.server import CowrieServer
        from cowrie.shell.session import SSHSessionForCowrieUser
        
        # Create a mock/fake realm
        realm = MagicMock()
        
        # CowrieServer.__init__ will initialize the user manager and seed system users
        server = CowrieServer(realm)
        
        # Check that users are seeded in the database
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM users WHERE username = 'developer'")
        self.assertGreater(cursor.fetchone()[0], 0)
        
        # Define a FakeAvatar for a new temporary user
        class FakeAvatar:
            def __init__(self, server, username, uid, gid, home):
                self.server = server
                self.username = username
                self.uid = uid
                self.gid = gid
                self.home = home
                self.temporary = True
                
        avatar = FakeAvatar(server, "student_new", 1007, 1007, "/home/student_new")
        
        # Instantiate SSHSessionForCowrieUser
        # Under the hood, this will call initFileSystem and mkdir for the home dir.
        # This must succeed without raising a PermissionDenied exception!
        sess = SSHSessionForCowrieUser(avatar)
        
        # Verify the home directory has been created and has correct owner credentials
        fs = server.fs
        # Query the filesystem database to check if /home/student_new exists and is owned by 1007:1007
        node = fs.getfile("/home/student_new")
        self.assertIsNotNone(node)
        self.assertEqual(node[2], 1007)  # UID
        self.assertEqual(node[3], 1007)  # GID

    def test_default_auth_checking(self) -> None:
        from cowrie.core.auth import UserDB
        db = UserDB()
        
        # Verify static credentials admin/admin123 succeeds
        self.assertTrue(db.checklogin(b"admin", b"admin123"))
        
        # Verify static credentials student/student123 succeeds
        self.assertTrue(db.checklogin(b"student", b"student123"))
        
        # Verify non-existent credentials fail
        self.assertFalse(db.checklogin(b"admin", b"wrongpass"))
        self.assertFalse(db.checklogin(b"attacker", b"password"))

    def test_mitre_mapping_and_threat_scores(self) -> None:
        # Link a session to a profile first
        session_id = "test_sess_mitre"
        profile_id = "test_profile_mitre"
        self.engine.memory_mgr.link_session(session_id, profile_id, "192.168.1.20", "SSH-2.0-OpenSSH_8.2p1")
        
        # Map a command that has multiple MITRE techniques (like sudo)
        mappings = self.engine.mitre_mgr.map_command(session_id, "sudo cat /etc/shadow")
        self.assertEqual(len(mappings), 2)
        self.assertTrue(any(m["technique"] == "T1548.001" for m in mappings))
        self.assertTrue(any(m["technique"] == "T1078" for m in mappings))
        
        # Map a system discovery command (like uname)
        self.engine.mitre_mgr.map_command(session_id, "uname -a")
        
        # Map a persistence command (like useradd)
        self.engine.mitre_mgr.map_command(session_id, "useradd test_user")
        
        # Compute threat scores
        scores = self.engine.threat_mgr.compute_threat_scores(profile_id)
        
        # Check sub-scores calculation
        # uname: Discovery -> Recon (1.0 * 5.0 = 5.0)
        # useradd: Persistence -> (1.0 * 8.0 = 8.0)
        # sudo: Privilege Escalation (0.9 * 7.0 = 6.3) + Defense Evasion (0.7 -> not in scores dict categories directly, but in overall)
        self.assertAlmostEqual(scores["recon"], 5.0)
        self.assertAlmostEqual(scores["persistence"], 8.0)
        self.assertAlmostEqual(scores["privilege_escalation"], 6.3)
        self.assertGreater(scores["overall"], 19.0)

    def test_behavior_profiler_and_features_persistence(self) -> None:
        session_id = "test_sess_behavior"
        profile_id = "test_profile_behavior"
        self.engine.memory_mgr.link_session(session_id, profile_id, "192.168.1.30", "SSH-2.0-OpenSSH_8.2p1")
        
        # Execute commands through behavioral profiler
        self.engine.behavior_profiler.analyze_command(session_id, "whoami", "/root", "root")
        self.engine.behavior_profiler.analyze_command(session_id, "id", "/root", "root")
        self.engine.behavior_profiler.analyze_command(session_id, "useradd test_u", "/root", "root")
        
        # Query profile behavior features
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM profile_behavior_features WHERE profile_id = ?", (profile_id,))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row["src_ip"], "192.168.1.30")
        self.assertEqual(row["client_banner"], "SSH-2.0-OpenSSH_8.2p1")
        
        # Verify first N commands list contains our commands
        import json
        cmds = json.loads(row["first_n_commands"])
        self.assertIn("whoami", cmds)
        self.assertIn("id", cmds)
        self.assertIn("useradd test_u", cmds)
        
        # Verify scores are stored
        self.assertGreater(row["recon_score"], 0.0)
        self.assertGreater(row["persistence_score"], 0.0)

    def test_shell_permission_errors_handling(self) -> None:
        from cowrie.shell.protocol import HoneyPotInteractiveProtocol
        from cowrie.test.fake_server import FakeServer, FakeAvatar
        from cowrie.test.fake_transport import FakeTransport
        
        class CustomFakeAvatar(FakeAvatar):
            def __init__(self, server, username, uid, gid, home):
                super().__init__(server)
                self.username = username
                self.uid = uid
                self.gid = gid
                self.home = home
                self.temporary = False
                self.environ = {
                    "LOGNAME": self.username,
                    "USER": self.username,
                    "HOME": self.home,
                    "TMOUT": "1800",
                    "PATH": "/usr/local/bin:/usr/bin:/bin"
                }
                
        server = MagicMock()
        server.fs = self.engine.fs_mgr
        avatar = CustomFakeAvatar(server, "admin", 1001, 1001, "/home/admin")
        proto = HoneyPotInteractiveProtocol(avatar)
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        
        # Force active persona to "amrita" for this test and seed
        self.engine.persona_mgr.active_persona = "amrita"
        if self.engine.fs_mgr.exists("/etc/persona_initialized"):
            self.engine.fs_mgr.remove("/etc/persona_initialized")
        self.engine.persona_mgr.setup_persona_in_db()
        
        # Switch to admin (owner)
        self.engine.fs_mgr.active_uid = 1001
        self.engine.fs_mgr.active_gid = 1001
        self.engine.fs_mgr.active_username = "admin"
        
        # Ensure /home/admin exists and is owned by admin
        self.assertTrue(self.engine.fs_mgr.exists("/home/admin"))
        
        # Owner can create directories
        tr.clear()
        proto.lineReceived(b"mkdir /home/admin/notes\n")
        self.assertTrue(self.engine.fs_mgr.exists("/home/admin/notes"))
        self.assertNotIn(b"Permission denied", tr.value())
        
        # Owner can touch files
        tr.clear()
        proto.lineReceived(b"touch /home/admin/file.txt\n")
        self.assertTrue(self.engine.fs_mgr.exists("/home/admin/file.txt"))
        self.assertNotIn(b"Permission denied", tr.value())
        
        # Restrict permissions of /home/admin to 700 to test cd/read denial for other users
        import stat
        self.engine.fs_mgr.update_metadata("/home/admin", mode=stat.S_IFDIR | 0o700)
        
        # Switch to non-owner (student)
        self.engine.fs_mgr.active_uid = 1004
        self.engine.fs_mgr.active_gid = 1004
        self.engine.fs_mgr.active_username = "student"
        avatar2 = CustomFakeAvatar(server, "student", 1004, 1004, "/home/student")
        proto2 = HoneyPotInteractiveProtocol(avatar2)
        tr2 = FakeTransport("", "31337")
        proto2.makeConnection(tr2)
        
        # Non-owner denied mkdir
        tr2.clear()
        proto2.lineReceived(b"mkdir /home/admin/notes2\n")
        self.assertIn(b"Permission denied", tr2.value())
        
        self.engine.fs_mgr.active_uid = 0
        self.assertFalse(self.engine.fs_mgr.exists("/home/admin/notes2"))
        self.engine.fs_mgr.active_uid = 1004
        
        # Non-owner denied touch
        tr2.clear()
        proto2.lineReceived(b"touch /home/admin/file2.txt\n")
        self.assertIn(b"Permission denied", tr2.value())
        
        self.engine.fs_mgr.active_uid = 0
        self.assertFalse(self.engine.fs_mgr.exists("/home/admin/file2.txt"))
        self.engine.fs_mgr.active_uid = 1004
        
        # Non-owner denied rm
        tr2.clear()
        proto2.lineReceived(b"rm /home/admin/file.txt\n")
        self.assertIn(b"Permission denied", tr2.value())
        
        self.engine.fs_mgr.active_uid = 0
        self.assertTrue(self.engine.fs_mgr.exists("/home/admin/file.txt"))
        self.engine.fs_mgr.active_uid = 1004
        
        # Non-owner denied rmdir
        tr2.clear()
        proto2.lineReceived(b"rmdir /home/admin/notes\n")
        self.assertIn(b"Permission denied", tr2.value())
        
        self.engine.fs_mgr.active_uid = 0
        self.assertTrue(self.engine.fs_mgr.exists("/home/admin/notes"))
        self.engine.fs_mgr.active_uid = 1004
        
        # Non-owner denied cd
        tr2.clear()
        proto2.cwd = "/"
        proto2.lineReceived(b"cd /home/admin\n")
        self.assertEqual(proto2.cwd, "/")
        self.assertIn(b"Permission denied", tr2.value())
        
        # Non-owner denied cat
        tr2.clear()
        proto2.lineReceived(b"cat /home/admin/file.txt\n")
        self.assertIn(b"Permission denied", tr2.value())
        
        # Session continues
        tr2.clear()
        proto2.lineReceived(b"pwd\n")
        self.assertIn(b"/\n", tr2.value())

    def test_multi_tenant_filesystem_isolation(self) -> None:
        # Resolve/create profile for Attacker A
        profile_id_A, conf_A, is_new_A = self.engine.memory_mgr.match_profile(
            session_id="session_A",
            username="root",
            src_ip="192.0.2.1",
            client_banner="SSH-2.0-OpenSSH_8.2",
            ssh_key="fingerprint_A"
        )
        self.assertTrue(is_new_A)
        self.assertIsNotNone(profile_id_A)
        self.engine.memory_mgr.link_session(
            session_id="session_A",
            profile_id=profile_id_A,
            src_ip="192.0.2.1",
            ssh_client="SSH-2.0-OpenSSH_8.2"
        )
        
        # Resolve/create profile for Attacker B (different IP and key)
        profile_id_B, conf_B, is_new_B = self.engine.memory_mgr.match_profile(
            session_id="session_B",
            username="root",
            src_ip="198.51.100.1",
            client_banner="SSH-2.0-OpenSSH_7.4",
            ssh_key="fingerprint_B"
        )
        self.assertTrue(is_new_B)
        self.assertIsNotNone(profile_id_B)
        self.assertNotEqual(profile_id_A, profile_id_B)
        self.engine.memory_mgr.link_session(
            session_id="session_B",
            profile_id=profile_id_B,
            src_ip="198.51.100.1",
            ssh_client="SSH-2.0-OpenSSH_7.4"
        )
        
        # Match Attacker A again (reconnection)
        profile_id_A2, conf_A2, is_new_A2 = self.engine.memory_mgr.match_profile(
            session_id="session_A2",
            username="root",
            src_ip="192.0.2.1",
            client_banner="SSH-2.0-OpenSSH_8.2",
            ssh_key="fingerprint_A"
        )
        self.assertFalse(is_new_A2)
        self.assertEqual(profile_id_A, profile_id_A2)
        
        # Test Filesystem Isolation:
        # Mount profile A filesystem
        self.engine.active_profile_id = profile_id_A
        self.engine.fs_mgr.active_profile_id = profile_id_A
        self.engine.fs_mgr.start("linux-x64-lsb", "/root")
        
        # Create a directory in profile A
        self.engine.fs_mgr.mkdir("/tmp/attacker_a_dir", 0, 0, 4096, 16877)
        self.assertTrue(self.engine.fs_mgr.exists("/tmp/attacker_a_dir"))
        
        # Mount profile B filesystem
        self.engine.active_profile_id = profile_id_B
        self.engine.fs_mgr.active_profile_id = profile_id_B
        self.engine.fs_mgr.start("linux-x64-lsb", "/root")
        
        # Verify directory does NOT exist in profile B
        self.assertFalse(self.engine.fs_mgr.exists("/tmp/attacker_a_dir"))
        
        # Create a directory in profile B
        self.engine.fs_mgr.mkdir("/tmp/attacker_b_dir", 0, 0, 4096, 16877)
        self.assertTrue(self.engine.fs_mgr.exists("/tmp/attacker_b_dir"))
        
        # Mount profile A again (reconnection)
        self.engine.active_profile_id = profile_id_A
        self.engine.fs_mgr.active_profile_id = profile_id_A
        
        # Verify profile A has its directory and NOT profile B's directory
        self.assertTrue(self.engine.fs_mgr.exists("/tmp/attacker_a_dir"))
        self.assertFalse(self.engine.fs_mgr.exists("/tmp/attacker_b_dir"))

        # Test Command History Namespacing:
        # Attacker A runs a command
        self.engine.behavior_profiler.analyze_command("session_A", "cat /etc/passwd", "/root", "root")
        
        # Attacker B runs a command
        self.engine.behavior_profiler.analyze_command("session_B", "uname -a", "/root", "root")
        
        # Verify bash history is scoped by profile
        cursor = self.engine.conn.cursor()
        
        # Under profile A
        cursor.execute("SELECT command FROM bash_history WHERE profile_id = ?", (profile_id_A,))
        commands_A = [r["command"] for r in cursor.fetchall()]
        self.assertIn("cat /etc/passwd", commands_A)
        self.assertNotIn("uname -a", commands_A)
        
        # Under profile B
        cursor.execute("SELECT command FROM bash_history WHERE profile_id = ?", (profile_id_B,))
        commands_B = [r["command"] for r in cursor.fetchall()]
        self.assertIn("uname -a", commands_B)
        self.assertNotIn("cat /etc/passwd", commands_B)


