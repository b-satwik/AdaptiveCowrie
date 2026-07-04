# loginctl command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_loginctl(HoneyPotCommand):
    def call(self) -> None:
        username = self.protocol.user.username
        
        # Output standard loginctl active sessions
        self.write("SESSION USER             SEAT             TTY             \n")
        self.write(f"      1 {username:<16s} seat0            pts/0           \n")
        self.write("\n1 sessions listed.\n")

commands["loginctl"] = Command_loginctl
commands["/usr/bin/loginctl"] = Command_loginctl
commands["/bin/loginctl"] = Command_loginctl
