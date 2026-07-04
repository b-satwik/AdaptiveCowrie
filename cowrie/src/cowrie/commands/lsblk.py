# lsblk command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_lsblk(HoneyPotCommand):
    def call(self) -> None:
        self.write("NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n")
        self.write("sda      8:0    0  100G  0 disk \n")
        self.write("├─sda1   8:1    0  512M  0 part /boot\n")
        self.write("└─sda2   8:2    0 99.5G  0 part /\n")
        self.write("sr0     11:0    1 1024M  0 rom  \n")

commands["/bin/lsblk"] = Command_lsblk
commands["lsblk"] = Command_lsblk
commands["/usr/bin/lsblk"] = Command_lsblk
