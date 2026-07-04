# mount command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_mount(HoneyPotCommand):
    def call(self) -> None:
        self.write("sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n")
        self.write("proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n")
        self.write("udev on /dev type devtmpfs (rw,nosuid,noexec,relatime,size=3971944k,nr_inodes=992986,mode=755)\n")
        self.write("devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)\n")
        self.write("tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=801048k,mode=755)\n")
        self.write("/dev/sda2 on / type ext4 (rw,relatime,errors=remount-ro)\n")
        self.write("tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n")

commands["/bin/mount"] = Command_mount
commands["mount"] = Command_mount
commands["/usr/bin/mount"] = Command_mount
