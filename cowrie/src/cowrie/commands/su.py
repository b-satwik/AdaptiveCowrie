# su command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_su(HoneyPotCommand):
    def call(self) -> None:
        username = self.args[0] if self.args else "root"
        
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()

        if not adaptive.enabled:
            # Fallback
            self.protocol.user.username = username
            self.protocol.user.uid = 0 if username == "root" else 1000
            self.protocol.user.gid = 0 if username == "root" else 1000
            self.write(f"Switched to user {username} (fallback)\n")
            return

        user = adaptive.user_mgr.get_user(username)
        if not user:
            self.write("su: Authentication failure\n")
            return

        # Switch context
        self.protocol.user.username = username
        self.protocol.user.uid = user["uid"]
        self.protocol.user.gid = user["gid"]
        self.protocol.environ["USER"] = username
        self.protocol.environ["HOME"] = user["home"]
        
        # Change cwd to home if it exists
        if self.protocol.fs.exists(user["home"]):
            self.protocol.cwd = user["home"]
        else:
            self.protocol.cwd = "/"

        # Log system authentication success
        adaptive.log_mgr.add_system_log(
            "/var/log/auth.log", "su",
            f"su: Successful su for {username} by {self.protocol.user.username or 'unknown'}"
        )

commands["su"] = Command_su
commands["/bin/su"] = Command_su
commands["/usr/bin/su"] = Command_su
