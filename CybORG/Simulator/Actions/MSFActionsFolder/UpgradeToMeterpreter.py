# Copyright DST Group. Licensed under the MIT license.
import string
from ipaddress import IPv4Address


from CybORG.Simulator.Actions.Action import lo
from CybORG.Simulator.Actions.MSFActionsFolder.MSFAction import MSFAction
# Upgrade a MSF_SHELL session to a METERPRETER session
from CybORG.Shared.Enums import SessionType, AppProtocol
from CybORG.Shared.Observation import Observation


class UpgradeToMeterpreter(MSFAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session=session, agent=agent)
        self.session_to_upgrade = target_session

    def execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent] or self.session_to_upgrade not in state.sessions[self.agent]:
            return obs
        server_session = state.sessions[self.agent][self.session]
        session_to_upgrade = state.sessions[self.agent][self.session_to_upgrade]

        # action fails if either chosen session is not active or of the correct type
        if server_session.session_type != SessionType.MSF_SERVER \
                or not (
                session_to_upgrade.session_type == SessionType.MSF_SHELL or session_to_upgrade.session_type == SessionType.METERPRETER) or not server_session.active \
                or not session_to_upgrade.active:
            return obs

        # find shared subnet of the two hosts
        server_interface = None
        up_interface = None
        # test if the two sessions are on the same host
        if server_session.hostname == session_to_upgrade.hostname:
            server_interface = server_session.hostname.get_interface(interface_name='lo')
        else:
            for upgrade_interface in state.hosts[session_to_upgrade.hostname].interfaces:
                if upgrade_interface.ip_address != lo:
                    server_session, server_interface = self.get_local_source_interface(local_session=server_session,
                                                                                       remote_address=upgrade_interface.ip_address,
                                                                                       state=state)
                if server_interface is not None:
                    up_interface = upgrade_interface
                    break

        if server_interface is None:
            return obs

        server_address = server_interface.ip_address
        upgrade_address = up_interface.ip_address

        obs.set_success(True)

        new_session = state.add_session(host=session_to_upgrade.hostname, agent=self.agent,
                                        user=session_to_upgrade.username, session_type="meterpreter",
                                        parent=server_session.ident)
        process = state.hosts[new_session.hostname].get_process(new_session.pid)
        process.ppid = session_to_upgrade.pid
        process.path = "/tmp/"
        # Randomly generate name:
        process.name = ''.join(state.np_random.choice(list(string.ascii_uppercase + string.ascii_lowercase)) for _ in range(5))
        local_port = state.hosts[session_to_upgrade.hostname].get_ephemeral_port()
        new_connection = {"Application Protocol": AppProtocol.TCP,
                          "remote_address": server_address,
                          "remote_port": 4433,
                          "local_address": upgrade_address,
                          "local_port": local_port}
        process.connections.append(new_connection)

        remote_port = {"local_port": 4433,
                       "Application Protocol": AppProtocol.TCP,
                       "local_address": server_address,
                       "remote_address": upgrade_address,
                       "remote_port": local_port
                       }
        state.hosts[server_session.hostname].get_process(server_session.pid).connections.append(remote_port)

        obs.add_session_info(hostid=str(self.session_to_upgrade), session_id=new_session.ident,
                             session_type=new_session.session_type, agent=self.agent)

        obs.add_process(hostid=str(server_address), local_address=server_address, local_port=4433,
                        remote_address=upgrade_address,
                        remote_port=local_port)
        obs.add_process(hostid=str(self.session_to_upgrade), local_address=upgrade_address, local_port=local_port,
                        remote_address=server_address,
                        remote_port=4433)
        return obs

    def __str__(self):
        return super(UpgradeToMeterpreter, self).__str__() + f", Shell Session: {self.session_to_upgrade}"

    def _format_log_msg(self, msg):
        return f"{self.__class__.__name__} : {msg} "
