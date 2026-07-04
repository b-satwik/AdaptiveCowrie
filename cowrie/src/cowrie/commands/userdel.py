# userdel command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_userdel(HoneyPotCommand):
    def call(self) -> None:
        if not self.args:
            self.write("userdel: missing username\n")
            return

        username = self.args[0]
        
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()

        if not adaptive.enabled:
            self.write(f"userdel: user {username} deleted (non-persistent).\n")
            return

        user = adaptive.user_mgr.get_user(username)
        if not user:
            self.write(f"userdel: user '{username}' does not exist\n")
            return

        success = adaptive.user_mgr.delete_user(username)
        if success:
            self.write(f"userdel: user '{username}' successfully deleted.\n")
            # Optionally clean up home directory
            home = f"/home/{username}"
            if self.protocol.fs.exists(home):
                try:
                    self.protocol.fs.rmdir(home)
                except Exception:
                    pass
        else:
            self.write(f"userdel: failed to delete user '{username}'\n")

commands["userdel"] = Command_userdel
commands["/usr/sbin/userdel"] = Command_userdel
commands["/sbin/userdel"] = Command_userdel
