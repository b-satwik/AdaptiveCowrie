# stat command for Cowrie

import stat
import time
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pwd import Group, Passwd

commands = {}

class Command_stat(HoneyPotCommand):
    def uid2name(self, uid: int) -> str:
        try:
            return Passwd().getpwuid(uid)["pw_name"]
        except Exception:
            return str(uid)

    def gid2name(self, gid: int) -> str:
        try:
            return Group().getgrgid(gid)["gr_name"]
        except Exception:
            return str(gid)

    def call(self) -> None:
        if not self.args:
            self.write("stat: missing operand\nTry 'stat --help' for more information.\n")
            return

        for path in self.args:
            resolved_path = self.protocol.fs.resolve_path(path, self.protocol.cwd)
            try:
                node = self.protocol.fs.getfile(resolved_path)
            except Exception:
                node = None

            if not node:
                self.write(f"stat: cannot stat '{path}': No such file or directory\n")
                continue

            name = node[0]
            node_type = node[1]
            uid = node[2]
            gid = node[3]
            size = node[4]
            mode = node[5]
            ctime = node[6]
            
            # Check for extended metadata fields
            mtime_val = node[10] if len(node) > 10 else ctime
            atime_val = node[11] if len(node) > 11 else ctime
            inode = node[12] if len(node) > 12 else 1042
            nlink = node[13] if len(node) > 13 else (2 if node_type == 1 else 1)

            # Determine file type description
            if node_type == 1: # Directory
                type_desc = "directory"
            elif node_type == 0: # File
                type_desc = "regular file"
            elif node_type == 2: # Link
                type_desc = "symbolic link"
            else:
                type_desc = "unknown"

            # Format mode permissions string
            perms = ["-"] * 10
            if mode & stat.S_IRUSR: perms[1] = "r"
            if mode & stat.S_IWUSR: perms[2] = "w"
            if mode & stat.S_IXUSR: perms[3] = "x"
            if mode & stat.S_IRGRP: perms[4] = "r"
            if mode & stat.S_IWGRP: perms[5] = "w"
            if mode & stat.S_IXGRP: perms[6] = "x"
            if mode & stat.S_IROTH: perms[7] = "r"
            if mode & stat.S_IWOTH: perms[8] = "w"
            if mode & stat.S_IXOTH: perms[9] = "x"
            perm_str = "".join(perms[1:])

            octal_mode = oct(mode & 0o7777)[2:]

            # Format times
            time_fmt = "%Y-%m-%d %H:%M:%S.000000000 +0000"
            access_str = time.strftime(time_fmt, time.localtime(atime_val))
            modify_str = time.strftime(time_fmt, time.localtime(mtime_val))
            change_str = time.strftime(time_fmt, time.localtime(ctime))

            self.write(f"  File: {path}\n")
            self.write(f"  Size: {size:<15d}Blocks: 8          IO Block: 4096   {type_desc}\n")
            self.write(f"Device: fd01h/64769d	Inode: {inode:<12d}Links: {nlink}\n")
            self.write(f"Access: ({octal_mode}/{perm_str})  Uid: ({uid:>5d}/{self.uid2name(uid):>8s})   Gid: ({gid:>5d}/{self.gid2name(gid):>8s})\n")
            self.write(f"Access: {access_str}\n")
            self.write(f"Modify: {modify_str}\n")
            self.write(f"Change: {change_str}\n")
            self.write(f" Birth: -\n")

commands["stat"] = Command_stat
commands["/usr/bin/stat"] = Command_stat
