# chmod command for Cowrie

import stat
import re
from cowrie.shell.command import HoneyPotCommand

commands = {}

MODE_REGEX = r"^[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=]?[0-7]+$"

class Command_chmod(HoneyPotCommand):
    def call(self) -> None:
        if not self.args or len(self.args) < 2:
            self.write("chmod: missing operand\nTry 'chmod --help' for more information.\n")
            return

        mode_str = self.args[0]
        files = self.args[1:]

        # Validate mode string
        if not re.match(MODE_REGEX, mode_str):
            self.write(f"chmod: invalid mode: ‘{mode_str}’\n")
            return

        for file in files:
            path = self.protocol.fs.resolve_path(file, self.protocol.cwd)
            if not self.protocol.fs.exists(path):
                self.write(f"chmod: cannot access '{file}': No such file or directory\n")
                continue

            node = self.protocol.fs.getfile(path)
            if not node:
                continue

            curr_mode = node[5]

            # Calculate new mode
            new_mode = curr_mode
            if mode_str.isdigit():
                # Octal mode
                try:
                    new_mode = int(mode_str, 8)
                    # Preserve type bits
                    type_bits = curr_mode & 0o170000
                    new_mode = type_bits | (new_mode & 0o7777)
                except ValueError:
                    self.write(f"chmod: invalid mode: ‘{mode_str}’\n")
                    continue
            else:
                # Symbolic mode (simple support for +x, -x, etc.)
                if "+x" in mode_str:
                    new_mode |= (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                elif "-x" in mode_str:
                    new_mode &= ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                elif "+r" in mode_str:
                    new_mode |= (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                elif "-r" in mode_str:
                    new_mode &= ~(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                elif "+w" in mode_str:
                    new_mode |= (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                elif "-w" in mode_str:
                    new_mode &= ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

            # Update metadata in VFS
            if hasattr(self.protocol.fs, "update_metadata"):
                self.protocol.fs.update_metadata(path, mode=new_mode)

commands["/bin/chmod"] = Command_chmod
commands["chmod"] = Command_chmod
