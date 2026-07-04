# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module contains the service commnad
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_service(HoneyPotCommand):
    """
    By Giannis Papaioannou <giannispapcod7@gmail.com>
    """

    def status_all(self) -> None:
        """
        List all services, querying the AdaptiveServiceManager if enabled.
        """
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        if adaptive.enabled:
            services = adaptive.service_mgr.list_services()
            for svc in services:
                sign = "+" if svc["status"] == "active" else "-"
                self.write(f" [ {sign} ]  {svc['name']}\n")
            return

        output = (
            "[ + ]  acpid",
            "[ - ]  alsa-utils",
            "[ + ]  anacron",
            "[ + ]  apparmor",
            "[ + ]  apport",
            "[ + ]  avahi-daemon",
            "[ + ]  bluetooth",
            "[ - ]  bootmisc.sh",
            "[ - ]  brltty",
            "[ - ]  checkfs.sh",
            "[ - ]  checkroot-bootclean.sh",
            "[ - ]  checkroot.sh",
            "[ + ]  console-setup",
            "[ + ]  cron",
            "[ + ]  cups",
            "[ + ]  cups-browsed",
            "[ + ]  dbus",
            "[ - ]  dns-clean",
            "[ + ]  grub-common",
            "[ - ]  hostname.sh",
            "[ - ]  hwclock.sh",
            "[ + ]  irqbalance",
            "[ - ]  kerneloops",
            "[ - ]  killprocs",
            "[ + ]  kmod",
            "[ + ]  lightdm",
            "[ - ]  mountall-bootclean.sh",
            "[ - ]  mountall.sh",
            "[ - ]  mountdevsubfs.sh",
            "[ - ]  mountkernfs.sh",
            "[ - ]  mountnfs-bootclean.sh",
            "[ - ]  mountnfs.sh",
            "[ + ]  network-manager",
            "[ + ]  networking",
            "[ + ]  ondemand",
            "[ + ]  open-vm-tools",
            "[ - ]  plymouth",
            "[ - ]  plymouth-log",
            "[ - ]  pppd-dns",
            "[ + ]  procps",
            "[ - ]  rc.local",
            "[ + ]  resolvconf",
            "[ - ]  rsync",
            "[ + ]  rsyslog",
            "[ - ]  saned",
            "[ - ]  sendsigs",
            "[ + ]  speech-dispatcher",
            "[ + ]  thermald",
            "[ + ]  udev",
            "[ + ]  ufw",
            "[ - ]  umountfs",
            "[ - ]  umountnfs.sh",
            "[ - ]  umountroot",
            "[ - ]  unattended-upgrades",
            "[ + ]  urandom",
            "[ - ]  uuidd",
            "[ + ]  whoopsie",
            "[ - ]  x11-common",
        )
        for line in output:
            self.write(line + "\n")

    def help(self) -> None:
        output = "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]"
        self.write(output + "\n")

    def call(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(
                self.args, "h", ["help", "status-all", "full-restart"]
            )
        except getopt.GetoptError:
            self.help()
            return

        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()

        if len(args) >= 2 and adaptive.enabled:
            name = args[0]
            action = args[1]
            if action == "start":
                if not adaptive.service_mgr.start_service(name):
                    self.write(f"{name}: unrecognized service\n")
            elif action == "stop":
                if not adaptive.service_mgr.stop_service(name):
                    self.write(f"{name}: unrecognized service\n")
            elif action == "restart":
                if not adaptive.service_mgr.restart_service(name):
                    self.write(f"{name}: unrecognized service\n")
            elif action == "status":
                svc = adaptive.service_mgr.get_service(name)
                if svc:
                    self.write(f" * {name} is {svc['status']}\n")
                else:
                    self.write(f"{name}: unrecognized service\n")
            return

        if not opts and not args:
            self.help()
            return

        for o, _a in opts:
            if o in ("--help") or o in ("-h"):
                self.help()
                return
            elif o in ("--status-all"):
                self.status_all()
        """
        Ubuntu shows no response when stopping, starting
        leviathan@ubuntu:~$ sudo service ufw stop
        leviathan@ubuntu:~$ sudo service ufw start
        leviathan@ubuntu:~$
        """


commands["/usr/sbin/service"] = Command_service
commands["service"] = Command_service
