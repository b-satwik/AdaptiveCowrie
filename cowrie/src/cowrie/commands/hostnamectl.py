# hostnamectl command for Cowrie

from cowrie.shell.command import HoneyPotCommand

commands = {}

class Command_hostnamectl(HoneyPotCommand):
    def call(self) -> None:
        from cowrie.adaptive.engine import AdaptiveEngine
        adaptive = AdaptiveEngine.get_instance()
        hostname = adaptive.persona_mgr.hostname if adaptive.enabled else "ubuntu"
        self.write(f"   Static hostname: {hostname}\n")
        self.write("         Icon name: computer-vm\n")
        self.write("           Chassis: vm\n")
        self.write("        Machine ID: 4be67da8470a4ef69d41bc58da20c1ea\n")
        self.write("           Boot ID: f88d3e91129b4e7fae44ebfa39d2c1ea\n")
        self.write("    Virtualization: oracle\n")
        self.write("  Operating System: Ubuntu 22.04.3 LTS\n")
        self.write("            Kernel: Linux 5.15.0-88-generic\n")
        self.write("      Architecture: x86-64\n")

commands["/bin/hostnamectl"] = Command_hostnamectl
commands["hostnamectl"] = Command_hostnamectl
commands["/usr/bin/hostnamectl"] = Command_hostnamectl
