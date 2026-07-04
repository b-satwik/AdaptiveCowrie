# df command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_df(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        used_kb = 9210452
        if adaptive.enabled:
            try:
                profile_id = getattr(self.protocol.fs, "profile_id", "default")
                cursor = adaptive.conn.cursor()
                cursor.execute("SELECT sum(size) FROM filesystem WHERE profile_id = ?", (profile_id,))
                db_size = cursor.fetchone()[0] or 0
                used_kb += int(db_size / 1024)
            except Exception:
                pass
                
        total_kb = 98290352
        avail_kb = total_kb - used_kb
        use_pct = int((used_kb / total_kb) * 100)

        self.write("Filesystem     1K-blocks    Used Available Use% Mounted on\n")
        self.write("udev             3971944       0   3971944   0% /dev\n")
        self.write("tmpfs             801048    1204    799844   1% /run\n")
        self.write(f"/dev/sda2       {total_kb} {used_kb}  {avail_kb}  {use_pct}% /\n")
        self.write("tmpfs            4005236       0   4005236   0% /dev/shm\n")
        self.write("tmpfs               5120       4      5116   1% /run/lock\n")
        self.write("/dev/sda1         523244    6120    517124   2% /boot\n")

commands["/bin/df"] = Command_df
commands["df"] = Command_df
commands["/usr/bin/df"] = Command_df
