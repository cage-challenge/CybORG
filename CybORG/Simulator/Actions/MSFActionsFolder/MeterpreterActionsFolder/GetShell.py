# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Simulator.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType, AppProtocol
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call shell from a meterpreter session - gives a shell session
# Note the shell command has been known to fail after a session or metasploit server has been open for an extended
# time. This is not currently reflected in the simulation action.
class GetShell(MeterpreterAction):
    def __init__(self, agent: str, session: int, target_session: int):
        super().__init__(session=session, agent=agent, target_session=target_session)

    def execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.meterpreter_session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.meterpreter_session]

        if session.session_type != SessionType.METERPRETER or not session.active:
            return obs

        obs.set_success(True)

        if session.hostname.os_type == OperatingSystemType.WINDOWS:
            obs.add_system_info(hostid="0", os_type=OperatingSystemType.WINDOWS,
                                os_distribution=session.hostname.distribution, os_version=session.hostname.version)

        new_session = state.add_session(host=session.hostname.hostname, agent=self.agent,
                                        user=session.user.username, session_type="msf shell", parent=session)
        process = new_session.process
        process.ppid = session.process.pid
        process.path = "/bin/"
        process.name = "sh"
        port1 = new_session.hostname.get_ephemeral_port()
        port2 = new_session.hostname.get_ephemeral_port()
        new_connection = {
            "local_port": port1,
            "local_address": IPv4Address("127.0.0.1"),
            "remote_port": port2,
          "remote_address": IPv4Address("127.0.0.1"),
            "Application Protocol": AppProtocol.TCP

        }
        process.connections.append(new_connection)

        new_connection2 = {
            "local_port": port2,
            "local_address": IPv4Address("127.0.0.1"),
            "remote_port": port1,
            "remote_address": IPv4Address("127.0.0.1"),
            "Application Protocol": AppProtocol.TCP
        }
        session.process.connections.append(new_connection2)

        obs.add_session_info(hostid="0", username=new_session.user.username, session_id=new_session.ident,
                             pid=new_session.process.pid, agent=self.agent, session_type=new_session.session_type)
        return obs
