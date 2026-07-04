# passwd command for Cowrie

import hashlib
from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_passwd(HoneyPotCommand):
    def start(self) -> None:
        self.username = self.args[0] if self.args else self.protocol.user.username
        
        from cowrie.adaptive.engine import AdaptiveEngine
        self.adaptive = AdaptiveEngine.get_instance()

        if not self.adaptive.enabled or not self.adaptive.user_mgr.get_user(self.username):
            self.write(f"passwd: user '{self.username}' does not exist\n")
            self.exit()
            return

        self.write("Enter new UNIX password: ")
        self.protocol.password_input = True
        self.stage = 1

    def lineReceived(self, line: str) -> None:
        line = line.strip()
        if self.stage == 1:
            self.new_password = line
            self.write("\nRetype new UNIX password: ")
            self.stage = 2
        elif self.stage == 2:
            if line == self.new_password:
                # Update password
                # Store SHA512 hash or similar
                salt = "salt123"
                pwd_hash = hashlib.sha512((line + salt).encode()).hexdigest()
                self.adaptive.user_mgr.change_password(self.username, pwd_hash)
                
                self.write("\npasswd: password updated successfully\n")
                self.protocol.password_input = False
                self.exit()
            else:
                self.write("\npasswd: passwords do not match\n")
                self.write("passwd: password unchanged\n")
                self.protocol.password_input = False
                self.exit()

commands["passwd"] = Command_passwd
commands["/usr/bin/passwd"] = Command_passwd
commands["/bin/passwd"] = Command_passwd
