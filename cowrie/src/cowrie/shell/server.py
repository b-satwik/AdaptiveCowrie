# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


from __future__ import annotations

import json
import random
from configparser import NoOptionError

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    In traditional Kippo each connection gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    def __init__(self, realm: IRealm) -> None:
        self.fs = None
        self.process = None
        
        # Extract transport and username via stack frame inspection
        import inspect
        frame = inspect.currentframe()
        transport = None
        username = None
        while frame:
            locs = frame.f_locals
            if "avatarId" in locs and not username:
                val = locs["avatarId"]
                if isinstance(val, bytes):
                    username = val.decode("utf-8", errors="ignore")
                elif isinstance(val, str):
                    username = val
            if "self" in locs:
                obj = locs["self"]
                if hasattr(obj, "transport") and hasattr(obj.transport, "getPeer"):
                    transport = obj.transport
                elif hasattr(obj, "transportId"):
                    transport = obj
            frame = frame.f_back

        session_id = None
        src_ip = "127.0.0.1"
        ssh_client = ""
        ssh_key = None

        if transport:
            session_id = getattr(transport, "transportId", None)
            if hasattr(transport, "otherVersionString") and transport.otherVersionString:
                ssh_client = transport.otherVersionString.decode("utf-8", errors="ignore")
            if hasattr(transport, "transport") and hasattr(transport.transport, "getPeer"):
                try:
                    src_ip = transport.transport.getPeer().host
                except Exception:
                    pass
            elif hasattr(transport, "getPeer"):
                try:
                    src_ip = transport.getPeer().host
                except Exception:
                    pass
            ssh_key = getattr(transport, "auth_pubkey_fingerprint", None)

        if not session_id:
            import uuid
            session_id = uuid.uuid4().hex[:12]

        self.session_id = session_id
        self.src_ip = src_ip
        self.ssh_client = ssh_client
        self.ssh_key = ssh_key

        from cowrie.adaptive.engine import AdaptiveEngine
        self.adaptive = AdaptiveEngine.get_instance()
        if self.adaptive.enabled:
            profile_id = "default"
            if hasattr(self.adaptive, "memory_mgr") and self.adaptive.memory_mgr.enabled:
                try:
                    profile_id, confidence, is_new = self.adaptive.memory_mgr.match_profile(
                        session_id=session_id,
                        username=username or "root",
                        src_ip=src_ip,
                        client_banner=ssh_client,
                        ssh_key=ssh_key
                    )
                    self.adaptive.memory_mgr.link_session(
                        session_id=session_id,
                        profile_id=profile_id,
                        src_ip=src_ip,
                        ssh_client=ssh_client
                    )
                except Exception as e:
                    log.msg(f"Adaptive Memory Engine error: {e}")

            self.profile_id = profile_id
            self.adaptive.active_profile_id = profile_id

            self.adaptive.user_mgr.start()
            self.adaptive.persona_mgr.start()
            self.adaptive.log_mgr.start()
            self.adaptive.honeytoken_mgr.start()
            self.hostname = self.adaptive.persona_mgr.hostname

            login_id = None
            try:
                import time
                cursor = self.adaptive.conn.cursor()
                cursor.execute(
                    "INSERT INTO last_logins (profile_id, username, tty, ip, login_time, logout_time) VALUES (?, ?, ?, ?, ?, ?)",
                    (profile_id, username or "root", "pts/0", src_ip, time.time(), None)
                )
                self.adaptive.conn.commit()
                login_id = cursor.lastrowid
            except Exception as e:
                log.msg(f"Error recording login: {e}")

            # Hook connection teardown
            orig_connectionLost = getattr(transport, "connectionLost", None)
            if orig_connectionLost:
                def new_connectionLost(reason):
                    try:
                        if self.adaptive.enabled:
                            if login_id is not None:
                                import time
                                cursor = self.adaptive.conn.cursor()
                                cursor.execute(
                                    "UPDATE last_logins SET logout_time = ? WHERE id = ? AND profile_id = ?",
                                    (time.time(), login_id, self.profile_id)
                                )
                                self.adaptive.conn.commit()
                            if hasattr(self.adaptive, "memory_mgr") and self.adaptive.memory_mgr.enabled:
                                self.adaptive.memory_mgr.link_logout(session_id)
                    except Exception as e:
                        log.msg(f"Error in connection teardown hook: {e}")
                    orig_connectionLost(reason)
                transport.connectionLost = new_connectionLost
        else:
            self.hostname = CowrieConfig.get("honeypot", "hostname", fallback="svr04")
        try:
            arches = [
                arch.strip()
                for arch in CowrieConfig.get(
                    "shell", "arch", fallback="linux-x64-lsb"
                ).split(",")
            ]
            self.arch = random.choice(arches)
        except NoOptionError:
            self.arch = "linux-x64-lsb"

        log.msg(f"Initialized emulated server as architecture: {self.arch}")

    def getCommandOutput(self, file):
        """
        Reads process output from JSON file.
        """
        with open(file, encoding="utf-8") as f:
            cmdoutput = json.load(f)
        return cmdoutput

    def initFileSystem(self, home):
        """
        Do this so we can trigger it later. Not all sessions need file system
        """
        self.fs = fs.HoneyPotFilesystem(self.arch, home, profile_id=getattr(self, "profile_id", "default"))
        self.fs.profile_id = getattr(self, "profile_id", "default")

        try:
            self.process = self.getCommandOutput(
                CowrieConfig.get("shell", "processes")
            )["command"]["ps"]
        except NoOptionError:
            self.process = None
