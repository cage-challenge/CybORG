# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Shared.Actions.ShellActionsFolder.OpenConnectionFolder.CredentialAccessFolder.CredentialAccess import CredentialAccess
from CybORG.Shared.Enums import SessionType, ProcessType
from CybORG.Shared.Observation import Observation


class SSHAccess(CredentialAccess):
    def __init__(self, session, agent, username, password, ip_address, port):
        super().__init__(session, agent)
        self.username = username
        self.password = password
        self.target = ip_address
        self.port = port

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if not session.active:
            return obs

        if session.session_type != SessionType.SHELL and session.session_type != SessionType.MSF_SHELL and session.session_type != SessionType.SSH:
            return obs

        # find shared subnet of the two hosts
        server_address = None
        target_host = None
        if self.target == IPv4Address("127.0.0.1"):
            server_address = IPv4Address("127.0.0.1")
            target_host = session.host
        else:
            for interface in session.host.interfaces:
                if self.target in interface.subnet.ip_addresses:
                    server_address = interface.ip_address
                    target_host = state.hosts[state.ip_addresses[self.target]]
                    break

        if server_address is None:
            return obs

        obs.add_interface_info(hostid="1", ip_address=str(self.target))

        ssh_proc = None
        port = None
        # should also check for a non-ssh process listening on port 22 - only extra info in obs will be that this
        # process exists on that port and IP
        for proc in target_host.processes:
            if proc.process_type == ProcessType.SSH:
                for conn in proc.connections:
                    if conn['local_port'] == self.port:
                        ssh_proc = proc
                        port = conn
                    break

        if ssh_proc is None or (
                port["local_address"] != IPv4Address("0.0.0.0") and port["local_address"] != self.target):

            return obs

        obs.add_process(hostid="1", local_address=str(self.target), local_port=22, status="open", app_protocol="ssh",
                        process_type="ssh")
        user_found = False
        # should really check all username password combinations (in order) in whatever file is used rather than just
        # user-user
        for user in target_host.users:
            if user.username == self.username and user.password == self.password:
                user_found = True
                break

        if user_found:
            obs.set_success(True)

            new_session = state.add_session(host=target_host.hostname, agent=self.agent,
                                            user=self.username, session_type="msf shell", parent=session)
            session.active = False
            process = new_session.process
            remote_port = session.host.get_ephemeral_port()
            new_connection = {"local_port": self.port,
                              "Application Protocol": "tcp",
                              "remote_address": server_address,
                              "remote_port": remote_port,
                              "local_address": self.target}
            process.connections.append(new_connection)

            remote_port_dict = {'local_port': remote_port,
                                "Application Protocol": "ssh",
                                "local_address": server_address,
                                "remote_address": self.target,
                                "remote_port": 22
                                }
            session.process.connections.append(remote_port_dict)

            obs.add_session_info(hostid="1", username=self.username, session_id=new_session.ident, session_type="ssh",
                                 timeout=0, agent=self.agent)
            obs.add_user_info(hostid="1", username=self.username, password=self.password)
            obs.add_system_info(hostid='1', os_type=target_host.os_type, hostname=target_host.hostname)

        return obs
