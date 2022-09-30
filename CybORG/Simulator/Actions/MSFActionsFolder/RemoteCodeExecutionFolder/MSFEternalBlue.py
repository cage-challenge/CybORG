# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address
from CybORG.Simulator.Actions.MSFActionsFolder.RemoteCodeExecutionFolder.RemoteCodeExecution import RemoteCodeExecution

# use msf module exploit/windows/smb/ms17_010_eternal_blue, set RHOSTS to target
# could also change LHOST, LPORT and RPORT (default 139)
# gives root session
from CybORG.Shared.Enums import SessionType, ProcessType, ProcessVersion, OperatingSystemType, OperatingSystemPatch
from CybORG.Shared.Observation import Observation


class MSFEternalBlue(RemoteCodeExecution):
    def __init__(self, ip_address: IPv4Address, session: int, agent: str):
        super().__init__(session=session, agent=agent)
        self.target = ip_address

    def execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.MSF_SERVER or not session.active:
            return obs

        # find shared subnet of the two hosts
        server_session, server_interface = self.get_local_source_interface(local_session=session, remote_address=self.target)

        if server_interface is None:
            return obs

        server_address = server_interface.ip_address

        if self.target == IPv4Address("127.0.0.1"):
            target_host = server_session.hostname
        else:
            target_host = state.hosts[state.ip_addresses[self.target]]

        # obs.add_interface_info(hostid='0', ip_address=server_address)
        # obs.add_interface_info(hostid='1', ip_address=self.target)

        # find out if smb is open
        smb_proc = None
        for proc in target_host.processes:
            if proc.process_type == ProcessType.SMB:
                # TODO: In case of SMB that is not the right version, should SMB process be in the obs?
                smb_proc = proc
                break

        # find out if smb is vulnerable (Windows OS + smb version)
        # Note that this exploit should actually work for all versions in the range Samba 3.0.20 - 3.0.25rc3
        if smb_proc is not None and smb_proc.version == ProcessVersion.SMBv1:
            obs.add_process(hostid="1", local_address=self.target, local_port=139, status="open",
                            process_type="smb")
            if target_host.os_type == OperatingSystemType.WINDOWS and OperatingSystemPatch.MS17_010:
                obs.set_success(True)

                root_user = None
                for u in state.hosts[state.ip_addresses[self.target]].users:
                    if u.username == "SYSTEM":
                        root_user = u

                new_session = state.add_session(host=target_host.hostname, agent=self.agent,
                                                user=root_user, session_type="meterpreter", parent=server_session.ident)

                local_port = target_host.get_ephemeral_port()
                new_connection = {"local_port": local_port,
                                  "Application Protocol": "tcp",
                                  "remote_address": server_address,
                                  "remote_port": 4444,
                                  "local_address": self.target
                                  }
                new_session.process.connections.append(new_connection)

                target_host.add_process(name="telnet", ppid=1, path="/usr/bin/", user=root_user)
                remote_port = {"local_port": 4444,
                               "Application Protocol": "tcp",
                               "local_address": server_address,
                               "remote_address": self.target,
                               "remote_port": local_port
                               }

                server_session.process.connections.append(remote_port)

                obs.add_process(hostid="0", local_address=server_address, remote_address=str(self.target),
                                local_port=4444, remote_port=local_port)
                obs.add_process(hostid="1", local_address=str(self.target), remote_address=server_address,
                                local_port=local_port, remote_port=4444)
                obs.add_session_info(hostid="1", session_id=new_session.ident, session_type=new_session.session_type, agent=self.agent)
            else:
                obs.add_interface_info(ip_address=str(self.target))

        return obs
