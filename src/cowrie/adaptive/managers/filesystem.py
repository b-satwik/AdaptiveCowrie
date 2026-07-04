# Adaptive Filesystem Manager for Cowrie

import os
import stat
import time
import errno
import fnmatch
import hashlib
import re
import pickle
import sqlite3
from typing import Any
from twisted.python import log
from cowrie.core.config import CowrieConfig

# VFS Node Indexes
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
A_MTIME, A_ATIME, A_INODE, A_NLINK = 10, 11, 12, 13
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(7)
SPECIAL_PATHS = ["/sys", "/proc", "/dev/pts"]

class AdaptiveFilesystemManager:
    def __init__(self, engine):
        self.engine = engine
        self.arch = "linux-x64-lsb"
        self.home = "/root"
        self.inode_counter = 1000
        
        # Temp files for SFTP/SCP
        self.tempfiles = {}
        self.filenames = {}
        self.newcount = 0
        self.pickle_fs = None

    @property
    def active_profile_id(self):
        return getattr(self, "_active_profile_id", "default")

    @active_profile_id.setter
    def active_profile_id(self, val):
        self._active_profile_id = val

    def start(self, arch: str, home: str):
        log.msg("=== AdaptiveFilesystemManager.start() called ===")
        self.arch = arch
        self.home = home
        
        # Load the original pickle fs for fallback
        self.pickle_fs = None
        pickle_path = CowrieConfig.get("shell", "filesystem", fallback="src/cowrie/data/fs.pickle")
        if os.path.exists(pickle_path):
            try:
                import pickle
                with open(pickle_path, "rb") as f:
                    self.pickle_fs = pickle.load(f)
            except Exception as e:
                log.msg(f"Failed to load fallback pickle fs: {e}")

        # Get max inode to initialize counter
        cursor = self.engine.conn.cursor()
        try:
            cursor.execute("SELECT max(inode) FROM filesystem WHERE profile_id = ?", (self.active_profile_id,))
            max_in = cursor.fetchone()[0]
            if max_in:
                self.inode_counter = max_in + 1
        except Exception:
            pass

        # Import default filesystem from pickle if DB is empty
        self.import_from_pickle()

        log.msg("=== import_from_pickle finished ===")

        # Seed root directory (/) if it doesn't exist in filesystem table
        try:
            cursor.execute("SELECT count(*) FROM filesystem WHERE path = '/' AND profile_id = ?", (self.active_profile_id,))
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    """INSERT OR IGNORE INTO filesystem 
                       (profile_id, path, parent, name, type, uid, gid, size, mode, ctime, mtime, atime, inode, nlink, target, realfile) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.active_profile_id, "/", None, "", T_DIR, 0, 0, 4096, stat.S_IFDIR | 0o755, time.time(), time.time(), time.time(), 2, 2, None, None)
                )
                log.msg("=== Root seeded ===")
                self.engine.conn.commit()
                log.msg("Root directory (/) successfully seeded in database.")
        except Exception as e:
            log.msg(f"Failed to seed root directory: {e}")
        
        # Load honeyfs contents mapping
        honeyfs_path = CowrieConfig.get("honeypot", "contents_path", fallback="honeyfs")
        if os.path.exists(honeyfs_path):
            self.init_honeyfs(honeyfs_path)

    def import_from_pickle(self):
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM filesystem WHERE profile_id = ?", (self.active_profile_id,))
        if cursor.fetchone()[0] > 0:
            return

        pickle_path = CowrieConfig.get("shell", "filesystem", fallback=CowrieConfig.get("honeypot", "filesystem", fallback="share/cowrie/fs.pickle"))
        if not os.path.exists(pickle_path):
            log.msg(f"Pickle filesystem not found at {pickle_path}, skipping import.")
            return

        log.msg(f"Importing initial filesystem from {pickle_path} into SQLite for profile {self.active_profile_id}...")
        try:
            with open(pickle_path, "rb") as f:
                fs_data = pickle.load(f)
            self.import_node("/", fs_data, cursor)
            self.engine.conn.commit()
            log.msg("Pickle filesystem successfully imported.")
        except Exception as e:
            log.err(f"Failed to import pickle filesystem: {e}")

    def import_node(self, path, node, cursor):
        name = node[A_NAME]
        node_type = node[A_TYPE]
        uid = node[A_UID]
        gid = node[A_GID]
        size = node[A_SIZE]
        mode = node[A_MODE]
        ctime = node[A_CTIME]
        target = node[A_TARGET] if len(node) > A_TARGET else None
        realfile = node[A_REALFILE] if len(node) > A_REALFILE else None

        parent = os.path.dirname(path) if path != "/" else None
        inode = self.inode_counter
        self.inode_counter += 1
        nlink = 2 if node_type == T_DIR else 1

        cursor.execute(
            """INSERT OR IGNORE INTO filesystem 
               (profile_id, path, parent, name, type, uid, gid, size, mode, ctime, mtime, atime, inode, nlink, target, realfile) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.active_profile_id, path, parent, name, node_type, uid, gid, size, mode, ctime, ctime, ctime, inode, nlink, target, realfile)
        )

        if node_type == T_DIR:
            for child in node[A_CONTENTS]:
                child_name = child[A_NAME]
                if path == "/":
                    child_path = "/" + child_name
                else:
                    child_path = path + "/" + child_name
                self.import_node(child_path, child, cursor)

    def init_honeyfs(self, honeyfs_path: str):
        cursor = self.engine.conn.cursor()
        for path, _directories, filenames in os.walk(honeyfs_path):
            for filename in filenames:
                realfile_path = os.path.join(path, filename)
                virtual_path = "/" + os.path.relpath(realfile_path, honeyfs_path)

                cursor.execute("SELECT * FROM filesystem WHERE path = ? AND type = ? AND profile_id = ?", (virtual_path, T_FILE, self.active_profile_id))
                if cursor.fetchone():
                    cursor.execute("UPDATE filesystem SET realfile = ? WHERE path = ? AND profile_id = ?", (realfile_path, virtual_path, self.active_profile_id))
        self.engine.conn.commit()

    def _row_to_node(self, row, query_contents=True) -> list:
        name = row['name']
        node_type = row['type']
        uid = row['uid']
        gid = row['gid']
        size = row['size']
        mode = row['mode']
        ctime = row['ctime']
        target = row['target']
        realfile = row['realfile']
        
        mtime = row['mtime'] if row['mtime'] is not None else ctime
        atime = row['atime'] if row['atime'] is not None else ctime
        inode = row['inode'] if row['inode'] is not None else 0
        nlink = row['nlink'] if row['nlink'] is not None else (2 if node_type == T_DIR else 1)

        contents = []
        if node_type == T_DIR and query_contents:
            cursor = self.engine.conn.cursor()
            cursor.execute("SELECT * FROM filesystem WHERE parent = ? AND profile_id = ?", (row['path'], self.active_profile_id))
            db_children = [self._row_to_node(child_row, query_contents=False) for child_row in cursor.fetchall()]
            children_dict = {c[A_NAME]: c for c in db_children}
            
            pickle_node = self.getfile_pickle(row['path'], follow_symlinks=False)
            if pickle_node and pickle_node[A_TYPE] == T_DIR:
                for p_child in pickle_node[A_CONTENTS]:
                    if p_child[A_NAME] not in children_dict:
                        children_dict[p_child[A_NAME]] = p_child
            contents = list(children_dict.values())

        return [name, node_type, uid, gid, size, mode, ctime, contents, target, realfile, mtime, atime, inode, nlink]

    def getfile_pickle(self, path: str, follow_symlinks: bool = True) -> list | None:
        if not self.pickle_fs:
            return None
        if path == "/":
            return self.pickle_fs
        pieces = path.strip("/").split("/")
        p = self.pickle_fs
        for piece in pieces:
            if not isinstance(p, list):
                return None
            names = [x[A_NAME] for x in p[A_CONTENTS]]
            if piece not in names:
                return None
            for x in p[A_CONTENTS]:
                if x[A_NAME] == piece:
                    p = x
                    break
        if p and p[A_TYPE] == T_LINK and follow_symlinks:
            target = p[A_TARGET]
            if target.startswith("/"):
                return self.getfile_pickle(target, follow_symlinks)
            else:
                resolved_target = os.path.normpath(os.path.join(os.path.dirname(path), target))
                return self.getfile_pickle(resolved_target, follow_symlinks)
        return p

    def _exists_raw(self, path: str) -> bool:
        if path == "/":
            return True
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        if cursor.fetchone()[0] > 0:
            return True
        return self.getfile(path, raw=True) is not None

    def _isdir_raw(self, path: str) -> bool:
        if path == "/":
            return True
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT type FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        row = cursor.fetchone()
        if row is not None:
            return row['type'] == T_DIR
        node = self.getfile(path, raw=True)
        return node is not None and node[A_TYPE] == T_DIR

    def check_permission(self, path: str, op: str) -> bool:
        """
        Check if active_uid/active_gid has permission op ('r', 'w', or 'x') on path.
        """
        if not self.engine.enabled:
            return True
        uid = getattr(self, "active_uid", 0)
        gid = getattr(self, "active_gid", 0)
        username = getattr(self, "active_username", "root")
        
        # Root override: bypasses all checks
        if uid == 0 or username == "root":
            return True

        # Enterprise permission model for admin user:
        if username == "admin":
            # Deny access to /root or /etc/shadow
            if path.startswith("/root") or path == "/etc/shadow":
                return False
            # Allow write/read in home, tmp, var/tmp, var/log, srv, etc/nginx, etc/apache2, etc/mysql
            admin_allowed_prefixes = [
                "/home/admin", "/tmp", "/var/tmp", "/var/log", "/srv", 
                "/etc/nginx", "/etc/apache2", "/etc/mysql"
            ]
            if any(path.startswith(p) for p in admin_allowed_prefixes):
                return True
            
        node = self.getfile(path, raw=True)
        if not node:
            # If path does not exist, permission checks depend on the parent directory write permissions
            parent_path = os.path.dirname(path)
            if parent_path == path:
                return True
            return self.check_permission(parent_path, "w")
            
        file_uid = node[A_UID]
        file_gid = node[A_GID]
        mode = node[A_MODE]
        
        # Determine user groups
        user_groups = {gid}
        user_obj = self.engine.user_mgr.get_user(username)
        if user_obj and user_obj.get("groups"):
            for gname in user_obj["groups"].split(","):
                gname = gname.strip()
                if not gname:
                    continue
                try:
                    from cowrie.shell.pwd import Group
                    g_entry = Group().getgrnam(gname)
                    user_groups.add(g_entry["gr_gid"])
                except Exception:
                    pass
                    
        # Check permissions based on owner, group, others
        if uid == file_uid:
            # Owner permissions
            mask = 0
            if op == "r": mask = 0o400
            elif op == "w": mask = 0o200
            elif op == "x": mask = 0o100
            return (mode & mask) != 0
        elif file_gid in user_groups:
            # Group permissions
            mask = 0
            if op == "r": mask = 0o040
            elif op == "w": mask = 0o020
            elif op == "x": mask = 0o010
            return (mode & mask) != 0
        else:
            # Others permissions
            mask = 0
            if op == "r": mask = 0o004
            elif op == "w": mask = 0o002
            elif op == "x": mask = 0o001
            return (mode & mask) != 0

    def check_traversal(self, path: str) -> bool:
        """
        Ensure all parent directories can be searched/traversed by the active user.
        """
        if not self.engine.enabled:
            return True
        uid = getattr(self, "active_uid", 0)
        username = getattr(self, "active_username", "root")
        if uid == 0 or username == "root":
            return True
            
        parts = path.strip("/").split("/")
        curr = ""
        for part in parts:
            if not part:
                continue
            curr = curr + "/" + part
            if self._exists_raw(curr) and self._isdir_raw(curr):
                if not self.check_permission(curr, "x"):
                    return False
        return True

    def getfile(self, path: str, follow_symlinks: bool = True, raw: bool = False) -> list | None:
        if not path:
            return None
        
        path = re.sub(r'//+', '/', path)
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        if not raw and not self.check_traversal(path):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        if path == "/":
            cursor = self.engine.conn.cursor()
            cursor.execute("SELECT * FROM filesystem WHERE parent = '/' AND profile_id = ?", (self.active_profile_id,))
            db_children = [self._row_to_node(r, query_contents=False) for r in cursor.fetchall()]
            children_dict = {c[A_NAME]: c for c in db_children}
            
            if self.pickle_fs and self.pickle_fs[A_TYPE] == T_DIR:
                for p_child in self.pickle_fs[A_CONTENTS]:
                    if p_child[A_NAME] not in children_dict:
                        children_dict[p_child[A_NAME]] = p_child
            
            now = time.time()
            return ["", T_DIR, 0, 0, 4096, stat.S_IFDIR | 0o755, now, list(children_dict.values()), None, None, now, now, 2, 2]

        curr_path = path
        for _ in range(8):
            cursor = self.engine.conn.cursor()
            cursor.execute("SELECT * FROM filesystem WHERE path = ? AND profile_id = ?", (curr_path, self.active_profile_id))
            row = cursor.fetchone()
            if not row:
                p_node = self.getfile_pickle(curr_path, follow_symlinks)
                if p_node and p_node[A_TYPE] == T_DIR:
                    p_node = list(p_node)
                    p_node[A_CONTENTS] = list(p_node[A_CONTENTS])
                    cursor = self.engine.conn.cursor()
                    cursor.execute("SELECT * FROM filesystem WHERE parent = ? AND profile_id = ?", (curr_path, self.active_profile_id))
                    db_children = [self._row_to_node(child_row, query_contents=False) for child_row in cursor.fetchall()]
                    children_dict = {c[A_NAME]: c for c in db_children}
                    for p_child in p_node[A_CONTENTS]:
                        if p_child[A_NAME] not in children_dict:
                            children_dict[p_child[A_NAME]] = p_child
                    p_node[A_CONTENTS] = list(children_dict.values())
                return p_node

            if row['type'] == T_LINK and follow_symlinks:
                target = row['target']
                if target.startswith("/"):
                    curr_path = target
                else:
                    curr_path = os.path.normpath(os.path.join(os.path.dirname(curr_path), target))
            else:
                return self._row_to_node(row, query_contents=True)

        return None

    def get_path(self, path: str, follow_symlinks: bool = True) -> list:
        path = self.resolve_path(path, os.path.dirname(path))
        if not self.check_permission(path, "r"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        node = self.getfile(path, follow_symlinks)
        if node is None:
            from cowrie.shell.fs import FileNotFound
            raise FileNotFound
        return node[A_CONTENTS]

    def listdir(self, path: str) -> list[str]:
        return [child[0] for child in self.get_path(path)]

    def exists(self, path: str) -> bool:
        if path == "/":
            return True
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        if cursor.fetchone()[0] > 0:
            return True
        return self.getfile(path) is not None

    def isdir(self, path: str) -> bool:
        if path == "/":
            return True
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT type FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        row = cursor.fetchone()
        if row is not None:
            return row['type'] == T_DIR
        node = self.getfile(path)
        return node is not None and node[A_TYPE] == T_DIR

    def islink(self, path: str) -> bool:
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT type FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        row = cursor.fetchone()
        return row is not None and row['type'] == T_LINK

    def file_contents(self, path: str) -> bytes:
        path = self.resolve_path(path, os.path.dirname(path))
        if not self.check_permission(path, "r"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")
        
        session_id = str(getattr(self, "sessionno", "default"))
        self.engine.honeytoken_mgr.check_interaction(session_id, path, os.path.dirname(path))

        # 1. Intercept passwd, shadow and group files
        if path == "/etc/passwd":
            users = self.engine.user_mgr.list_users()
            lines = []
            for u in users:
                lines.append(f"{u['username']}:{u['password']}:{u['uid']}:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}\n")
            return "".join(lines).encode()

        if path == "/etc/shadow":
            users = self.engine.user_mgr.list_users()
            lines = []
            for u in users:
                pwd = u['password']
                if pwd == "x" or pwd == "!!":
                    pwd = "$6$rounds=40960$salt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash"
                lines.append(f"{u['username']}:{pwd}:19000:0:99999:7:::\n")
            return "".join(lines).encode()

        if path == "/etc/group":
            users = self.engine.user_mgr.list_users()
            group_members = {}
            for u in users:
                for gname in u['groups'].split(","):
                    gname = gname.strip()
                    if gname:
                        if gname not in group_members:
                            group_members[gname] = []
                        if u['username'] not in group_members[gname]:
                            group_members[gname].append(u['username'])
            
            group_gids = {
                "root": 0, "daemon": 1, "bin": 2, "sys": 3, "adm": 4, "tty": 5, "disk": 6, "lp": 7, "mail": 8, "news": 9,
                "uucp": 10, "man": 12, "proxy": 13, "kmem": 15, "dialout": 20, "fax": 21, "voice": 22, "cdrom": 24,
                "floppy": 25, "tape": 26, "sudo": 27, "audio": 29, "dip": 30, "www-data": 33, "backup": 34, "operator": 37,
                "list": 38, "irc": 39, "src": 40, "gnats": 41, "shadow": 42, "utmp": 43, "video": 44, "sasl": 45,
                "plugdev": 46, "staff": 50, "games": 60, "users": 100, "nogroup": 65534
            }

            lines = []
            for gname, members in group_members.items():
                member_str = ",".join(members)
                # Map to mock GID or look up from users or default to 1000
                gid = group_gids.get(gname)
                if gid is None:
                    # Look up from users
                    for u in users:
                        if u['username'] == gname:
                            gid = u['gid']
                            break
                if gid is None:
                    gid = 1000
                lines.append(f"{gname}:x:{gid}:{member_str}\n")
            return "".join(lines).encode()

        # 2. Check SQLite contents database
        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT content FROM file_contents WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        row = cursor.fetchone()
        if row:
            return row['content']

        # 4. Check for logs generation dynamically if no custom content written
        if path in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log") or "nginx" in path or "apache" in path or "mysql" in path:
            return self.engine.log_mgr.generate_log_content(path)

        f = self.getfile(path)
        if not f:
            from cowrie.shell.fs import FileNotFound
            raise FileNotFound(f"VFS: {path} not found")
        if f[A_TYPE] == T_DIR:
            raise IsADirectoryError

        # Try HoneyFS realfile contents
        if len(f) > A_REALFILE and f[A_REALFILE] and os.path.exists(f[A_REALFILE]):
            with open(f[A_REALFILE], "rb") as host_f:
                return host_f.read()

        # Fallback to arch binary if executable
        if f[A_MODE] & stat.S_IXUSR:
            arch_file = CowrieConfig.get("honeypot", "data_path") + "/arch/" + self.arch
            if os.path.exists(arch_file):
                with open(arch_file, "rb") as host_f:
                    return host_f.read()

        return b""

    def mkfile(self, path: str, uid: int, gid: int, size: int, mode: int, ctime: float | None = None) -> bool:
        if ctime is None:
            ctime = time.time()
        path = self.resolve_path(path, os.path.dirname(path))
        if not self.check_permission(path, "w"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        if any([path.startswith(p) for p in SPECIAL_PATHS]):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        parent = os.path.dirname(path)
        name = os.path.basename(path)
        inode = self.inode_counter
        self.inode_counter += 1

        cursor = self.engine.conn.cursor()
        cursor.execute("DELETE FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        cursor.execute(
            """INSERT INTO filesystem 
               (profile_id, path, parent, name, type, uid, gid, size, mode, ctime, mtime, atime, inode, nlink, target, realfile) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.active_profile_id, path, parent, name, T_FILE, uid, gid, size, mode, ctime, ctime, ctime, inode, 1, None, None)
        )
        self.engine.conn.commit()
        return True

    def mkdir(self, path: str, uid: int, gid: int, size: int, mode: int, ctime: float | None = None):
        if ctime is None:
            ctime = time.time()
        path = self.resolve_path(path, os.path.dirname(path))
        if not self.check_permission(path, "w"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        parent = os.path.dirname(path)
        name = os.path.basename(path)
        inode = self.inode_counter
        self.inode_counter += 1

        cursor = self.engine.conn.cursor()
        cursor.execute(
            """INSERT OR REPLACE INTO filesystem 
               (profile_id, path, parent, name, type, uid, gid, size, mode, ctime, mtime, atime, inode, nlink, target, realfile) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.active_profile_id, path, parent, name, T_DIR, uid, gid, size, mode, ctime, ctime, ctime, inode, 2, None, None)
        )
        self.engine.conn.commit()

    def remove(self, path: str) -> None:
        path = self.resolve_path(path, os.path.dirname(path))
        parent = os.path.dirname(path)
        if not self.check_permission(parent, "w"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")
        
        # Intercept log removals
        if path in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log") or "nginx" in path or "apache" in path or "mysql" in path:
            self.engine.log_mgr.handle_log_write(path, b"")

        cursor = self.engine.conn.cursor()
        cursor.execute("DELETE FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        cursor.execute("DELETE FROM file_contents WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        self.engine.conn.commit()

    def rmdir(self, path: str) -> bool:
        path = self.resolve_path(path, os.path.dirname(path))
        parent = os.path.dirname(path)
        if not self.check_permission(parent, "w"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT count(*) FROM filesystem WHERE parent = ? AND profile_id = ?", (path, self.active_profile_id))
        if cursor.fetchone()[0] > 0:
            raise OSError(errno.ENOTEMPTY, os.strerror(errno.ENOTEMPTY), path)
        
        cursor.execute("DELETE FROM filesystem WHERE path = ? AND profile_id = ?", (path, self.active_profile_id))
        self.engine.conn.commit()
        return True

    def rename(self, oldpath: str, newpath: str) -> None:
        oldpath = self.resolve_path(oldpath, os.path.dirname(oldpath))
        newpath = self.resolve_path(newpath, os.path.dirname(newpath))
        old_parent = os.path.dirname(oldpath)
        new_parent = os.path.dirname(newpath)
        if not self.check_permission(old_parent, "w") or not self.check_permission(new_parent, "w"):
            from cowrie.shell.fs import PermissionDenied
            raise PermissionDenied("Permission Denied")

        cursor = self.engine.conn.cursor()
        cursor.execute("SELECT * FROM filesystem WHERE path = ? AND profile_id = ?", (oldpath, self.active_profile_id))
        old_row = cursor.fetchone()
        if not old_row:
            from cowrie.shell.fs import FileNotFound
            raise FileNotFound
        
        new_parent = os.path.dirname(newpath)
        new_name = os.path.basename(newpath)

        cursor.execute(
            """INSERT OR REPLACE INTO filesystem 
               (profile_id, path, parent, name, type, uid, gid, size, mode, ctime, mtime, atime, inode, nlink, target, realfile) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.active_profile_id, newpath, new_parent, new_name, old_row['type'], old_row['uid'], old_row['gid'], 
             old_row['size'], old_row['mode'], old_row['ctime'], old_row['mtime'], old_row['atime'], 
             old_row['inode'], old_row['nlink'], old_row['target'], old_row['realfile'])
        )
        cursor.execute("DELETE FROM filesystem WHERE path = ? AND profile_id = ?", (oldpath, self.active_profile_id))

        # Update file contents
        cursor.execute("SELECT content FROM file_contents WHERE path = ? AND profile_id = ?", (oldpath, self.active_profile_id))
        content_row = cursor.fetchone()
        if content_row:
            cursor.execute("INSERT OR REPLACE INTO file_contents (profile_id, path, content) VALUES (?, ?, ?)", (self.active_profile_id, newpath, content_row['content']))
            cursor.execute("DELETE FROM file_contents WHERE path = ? AND profile_id = ?", (oldpath, self.active_profile_id))

        # Update children if directory
        if old_row['type'] == T_DIR:
            cursor.execute("SELECT path FROM filesystem WHERE path LIKE ? AND profile_id = ?", (oldpath + "/%", self.active_profile_id))
            children = [row['path'] for row in cursor.fetchall()]
            for child_path in children:
                suffix = child_path[len(oldpath):]
                new_child_path = newpath + suffix
                new_child_parent = os.path.dirname(new_child_path)
                cursor.execute("UPDATE filesystem SET path = ?, parent = ? WHERE path = ? AND profile_id = ?", (new_child_path, new_child_parent, child_path, self.active_profile_id))
                
                # Also update child contents
                cursor.execute("SELECT content FROM file_contents WHERE path = ? AND profile_id = ?", (child_path, self.active_profile_id))
                child_content = cursor.fetchone()
                if child_content:
                    cursor.execute("INSERT OR REPLACE INTO file_contents (profile_id, path, content) VALUES (?, ?, ?)", (self.active_profile_id, new_child_path, child_content['content']))
                    cursor.execute("DELETE FROM file_contents WHERE path = ? AND profile_id = ?", (child_path, self.active_profile_id))

        self.engine.conn.commit()

    def update_metadata(self, path: str, uid: int | None = None, gid: int | None = None, mode: int | None = None, mtime: float | None = None, atime: float | None = None, ctime: float | None = None) -> None:
        path = self.resolve_path(path, os.path.dirname(path))
        cursor = self.engine.conn.cursor()
        
        updates = []
        params = []
        
        if uid is not None:
            updates.append("uid = ?")
            params.append(uid)
        if gid is not None:
            updates.append("gid = ?")
            params.append(gid)
        if mode is not None:
            updates.append("mode = ?")
            params.append(mode)
        if mtime is not None:
            updates.append("mtime = ?")
            params.append(mtime)
        if atime is not None:
            updates.append("atime = ?")
            params.append(atime)
        if ctime is not None:
            updates.append("ctime = ?")
            params.append(ctime)
            
        if not updates:
            return
            
        params.append(path)
        params.append(self.active_profile_id)
        query = f"UPDATE filesystem SET {', '.join(updates)} WHERE path = ? AND profile_id = ?"
        cursor.execute(query, tuple(params))
        self.conn = self.engine.conn
        self.conn.commit()

    def resolve_path(self, path: str, cwd: str) -> str:
        if not path:
            return cwd
        if path.startswith("~/"):
            path = self.home + path[1:]
            
        if path.startswith("/"):
            resolved = path
        else:
            resolved = os.path.join(cwd, path)
        
        resolved = os.path.normpath(resolved)
        if not resolved:
            resolved = "/"
        return resolved

    def realpath(self, path: str) -> str:
        return self.resolve_path(path, os.path.dirname(path))

    def update_size(self, filename: str, size: int) -> None:
        filename = self.resolve_path(filename, os.path.dirname(filename))
        cursor = self.engine.conn.cursor()
        cursor.execute("UPDATE filesystem SET size = ?, mtime = ? WHERE path = ? AND profile_id = ?", (size, time.time(), filename, self.active_profile_id))
        self.engine.conn.commit()

    def update_realfile(self, f: Any, realfile: str) -> None:
        if not f:
            return
        name = f[0]
        cursor = self.engine.conn.cursor()
        cursor.execute("UPDATE filesystem SET realfile = ? WHERE name = ? AND realfile IS NULL AND profile_id = ?", (realfile, name, self.active_profile_id))
        self.engine.conn.commit()

    def write_file_content(self, path: str, content: bytes) -> None:
        path = self.resolve_path(path, os.path.dirname(path))
        
        # Check if intercept log writes
        if path in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log") or "nginx" in path or "apache" in path or "mysql" in path:
            self.engine.log_mgr.handle_log_write(path, content)
            return

        cursor = self.engine.conn.cursor()
        if not self.exists(path):
            self.mkfile(path, 0, 0, len(content), stat.S_IFREG | 0o644)
        else:
            cursor.execute("UPDATE filesystem SET size = ?, mtime = ? WHERE path = ? AND profile_id = ?", (len(content), time.time(), path, self.active_profile_id))
            
        cursor.execute("INSERT OR REPLACE INTO file_contents (profile_id, path, content) VALUES (?, ?, ?)", (self.active_profile_id, path, content))
        self.engine.conn.commit()
