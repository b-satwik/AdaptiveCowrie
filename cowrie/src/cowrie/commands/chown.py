# chown command for Cowrie

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pwd import Passwd, Group

commands = {}

class Command_chown(HoneyPotCommand):
    def name2uid(self, name: str) -> int | None:
        try:
            return Passwd().getpwnam(name)["pw_uid"]
        except Exception:
            if name.isdigit():
                return int(name)
            return None

    def name2gid(self, name: str) -> int | None:
        try:
            return Group().getgrnam(name)["gr_gid"]
        except Exception:
            if name.isdigit():
                return int(name)
            return None

    def call(self) -> None:
        if not self.args or len(self.args) < 2:
            self.write("chown: missing operand\nTry 'chown --help' for more information.\n")
            return

        owner_group = self.args[0]
        files = self.args[1:]

        # Split owner and group
        owner = None
        group = None
        if ":" in owner_group:
            parts = owner_group.split(":", 1)
            owner = parts[0]
            group = parts[1]
        elif "." in owner_group:
            parts = owner_group.split(".", 1)
            owner = parts[0]
            group = parts[1]
        else:
            owner = owner_group

        uid = self.name2uid(owner) if owner else None
        gid = self.name2gid(group) if group else None

        for file in files:
            path = self.protocol.fs.resolve_path(file, self.protocol.cwd)
            if not self.protocol.fs.exists(path):
                self.write(f"chown: cannot access '{file}': No such file or directory\n")
                continue

            if hasattr(self.protocol.fs, "update_metadata"):
                self.protocol.fs.update_metadata(path, uid=uid, gid=gid)

commands["chown"] = Command_chown
commands["/bin/chown"] = Command_chown
commands["/usr/bin/chown"] = Command_chown
