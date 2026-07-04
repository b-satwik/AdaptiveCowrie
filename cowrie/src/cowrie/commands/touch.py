# touch command for Cowrie

import stat
import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_touch(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.write("touch: missing file operand\nTry 'touch --help' for more information.\n")
            return

        now = time.time()
        for path in self.args:
            resolved_path = self.protocol.fs.resolve_path(path, self.protocol.cwd)
            
            # Check if file exists
            if self.protocol.fs.exists(resolved_path):
                # Update times
                if hasattr(self.protocol.fs, "update_metadata"):
                    self.protocol.fs.update_metadata(resolved_path, mtime=now, atime=now)
            else:
                # Create empty file
                try:
                    uid = self.protocol.user.uid
                    gid = self.protocol.user.gid
                    self.protocol.fs.mkfile(resolved_path, uid, gid, 0, stat.S_IFREG | 0o644, ctime=now)
                except Exception as e:
                    self.write(f"touch: cannot touch '{path}': Permission denied\n")

commands["touch"] = Command_touch
commands["/bin/touch"] = Command_touch
commands["/usr/bin/touch"] = Command_touch
