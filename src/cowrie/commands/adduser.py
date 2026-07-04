# adduser and useradd command for Cowrie

import stat
import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_adduser(HoneyPotCommand):
    def start(self) -> None:
        cmd_name = self.environ.get("COMMAND_LINE", "adduser").split()[0].strip().split("/")[-1]
        
        # Parse username from args
        self.username = None
        for arg in self.args:
            if not arg.startswith("-") and not arg.isdigit():
                self.username = arg
                break

        if not self.username:
            self.write(f"{cmd_name}: Only one or two names allowed.\n")
            self.exit()
            return

        from cowrie.adaptive.engine import AdaptiveEngine
        self.adaptive = AdaptiveEngine.get_instance()

        if cmd_name == "useradd":
            # Non-interactive useradd
            self.run_useradd()
        else:
            # Interactive adduser (mock dialog ending in registration)
            self.write(f"Adding user `{self.username}' ...\n")
            self.write(f"Adding new group `{self.username}' (1001) ...\n")
            self.write(f"Adding new user `{self.username}' (1001) with group `{self.username}' ...\n")
            self.write(f"Creating home directory `/home/{self.username}' ...\n")
            self.write("Copying files from `/etc/skel' ...\n")
            
            # Persistently add user
            self.register_user()
            self.write("passwd: password updated successfully\n")
            self.exit()

    def run_useradd(self) -> None:
        self.register_user()
        self.exit()

    def register_user(self) -> None:
        if self.adaptive.enabled:
            # Add to user database
            success = self.adaptive.user_mgr.add_user(self.username)
            if success:
                # Create VFS home directory
                home_dir = f"/home/{self.username}"
                if not self.protocol.fs.exists(home_dir):
                    self.protocol.fs.mkdir(home_dir, 1001, 1001, 4096, stat.S_IFDIR | 0o755)
                    # Seed standard shell files
                    self.protocol.fs.write_file_content(f"{home_dir}/.bashrc", b"# .bashrc\n")
                    self.protocol.fs.write_file_content(f"{home_dir}/.profile", b"# .profile\n")
                    self.protocol.fs.write_file_content(f"{home_dir}/.bash_logout", b"# logout\n")
        else:
            self.write(f"User {self.username} added (non-persistent fallback).\n")

commands["/usr/sbin/adduser"] = Command_adduser
commands["/usr/sbin/useradd"] = Command_adduser
commands["/sbin/useradd"] = Command_adduser
commands["adduser"] = Command_adduser
commands["useradd"] = Command_adduser
