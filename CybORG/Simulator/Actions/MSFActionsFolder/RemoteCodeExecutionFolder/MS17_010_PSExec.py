# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address
from time import sleep

from CybORG.Simulator.Actions.MSFActionsFolder.RemoteCodeExecutionFolder.RemoteCodeExecution import RemoteCodeExecution

# use msf module exploit/windows/smb/ms17_010_eternal_blue, set RHOSTS to target
# could also change LHOST, LPORT and RPORT (default 139)
# gives root session
from CybORG.Shared.Enums import SessionType, OperatingSystemType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.User import User


class MS17_010_PSExec(RemoteCodeExecution):
    def __init__(self, ip_address: IPv4Address, session: int, agent: str, username: str, password: str):
        super().__init__(session=session, agent=agent)
        self.target = ip_address
        self.username = username
        self.password = password
        self.port = 139

    def execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.MSF_SERVER or not session.active:
            return obs
        target_subnet = None
        for subnet in state.subnets.values():
            if self.target in subnet.ip_addresses:
                target_subnet = subnet
                break
        if target_subnet is None:
            return obs
        # find shared subnet of the two hosts
        server_session, server_interface = self.get_local_source_interface(local_session=session, remote_address=self.target, state=state)

        if server_interface is None:
            return obs

        server_address = server_interface.ip_address

        if self.target == IPv4Address("127.0.0.1"):
            target_host = server_session.hostname
        else:
            target_host = state.hosts[state.ip_addresses[self.target]]
            if not self.test_nacl(port=self.port, target_subnet=target_subnet,
                                  originating_subnet=state.subnets[server_interface.subnet]):
                return obs

        # find out if smb is open
        smb_proc = None
        for proc in target_host.processes:
            for conn in proc.connections:
                if conn['local_port'] == self.port and 'remote_address' not in conn:
                # if proc.process_type == ProcessType.SMB:
                # TODO: In case of SMB that is not the right version, should SMB process be in the obs?
                    smb_proc = proc
                    break

        # find out if smb is vulnerable (Windows OS + smb version)
        # Note that this exploit should actually work for all versions in the range Samba 3.0.20 - 3.0.25rc3
        if smb_proc is not None:# and smb_proc.version == ProcessVersion.SMBv1:
            obs.add_process(hostid=str(self.target), local_address=self.target, local_port=self.port, status="open",
                            process_type="smb")
            if target_host.os_type == OperatingSystemType.WINDOWS:
                obs.set_success(True)

                root_user: User = None
                for u in state.hosts[state.ip_addresses[self.target]].users:
                    if u.username == "SYSTEM":
                        root_user = u

                new_session = state.add_session(host=target_host.hostname, agent=self.agent,
                                                user=root_user.username, session_type="meterpreter", parent=server_session.ident)

                local_port = target_host.get_ephemeral_port()
                new_connection = {"remote_port": local_port,
                                  "Application Protocol": "tcp",
                                  "remote_address": server_address,
                                  "local_port": 44444,
                                  "local_address": self.target
                                  }
                state.hosts[new_session.hostname].get_process(new_session.pid).connections.append(new_connection)

                target_host.add_process(name="telnet", ppid=1, path="/usr/bin/", user=root_user)
                remote_port = {"remote_port": 44444,
                               "Application Protocol": "tcp",
                               "local_address": server_address,
                               "remote_address": self.target,
                               "local_port": local_port
                               }

                state.hosts[server_session.hostname].get_process(server_session.pid).connections.append(remote_port)
                if session != server_session:
                    local_port = None
                obs.add_process(hostid=str(self.target), local_address=str(self.target), remote_address=server_address,
                                remote_port=local_port, local_port=44444)
                obs.add_session_info(hostid=str(self.target), session_id=int(new_session.ident), session_type=new_session.session_type, agent=self.agent)
            else:
                obs.add_interface_info(ip_address=str(self.target))

        return obs

    def __str__(self):
        return super(MS17_010_PSExec, self).__str__() + f", Target: {self.target}, Username: {self.username}, " \
                                                        f"Password: {self.password}"

    def _format_log_msg(self, msg):
        return f"{self.__class__.__name__} : {msg}"