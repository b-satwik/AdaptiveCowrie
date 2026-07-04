# arp command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_arp(HoneyPotCommand):
    def call(self) -> None:
        self.write("Address                  HWtype  HWaddress           Flags Mask            Iface\n")
        self.write("192.168.1.1              ether   52:54:00:12:34:01   C                     eth0\n")

commands["arp"] = Command_arp
commands["/usr/sbin/arp"] = Command_arp
commands["/sbin/arp"] = Command_arp
