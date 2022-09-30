# Copyright DST Group. Licensed under the MIT license.
import string
import random

from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import MSFAction
from CybORG.Shared.Enums import SessionType, AppProtocol, OperatingSystemType
from CybORG.Shared.Observation import Observation


# Create a Windows service which runs an executable for persistence.


class ServicePersistenceWindows(MSFAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session=session, agent=agent)
        self.session = session
        self.session_to_persist = target_session

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)

        if self.session not in state.sessions[self.agent] or self.session_to_persist not in state.sessions[self.agent]:
            return obs
        server_session = state.sessions[self.agent][self.session]
        session_to_persist = state.sessions[self.agent][self.session_to_persist]

        if server_session.session_type != SessionType.MSF_SERVER \
                or session_to_persist.session_type != SessionType.METERPRETER or not server_session.active \
                or not session_to_persist.active:
            return obs

        if not any(group.name == 'ADMINISTRATORS' for group in session_to_persist.user.groups) \
                and session_to_persist.user.username != 'SYSTEM':
            return obs

        if session_to_persist.host.os_type != OperatingSystemType.WINDOWS:
            return obs

        # find shared subnet of the two hosts
        server_interface = None
        per_interface = None
        for persist_interface in session_to_persist.host.interfaces:
            server_session, server_interface = self.get_local_source_interface(local_session=server_session,
                                                                               remote_address=persist_interface.ip_address,
                                                                               state=state)
            if server_interface is not None:
                per_interface = persist_interface
                break

        if server_interface is None:
            return obs

        server_address = server_interface.ip_address
        persist_address = per_interface.ip_address

        obs.set_success(True)

        new_session = state.add_session(host=session_to_persist.host.hostname, agent=self.agent,
                                        user=session_to_persist.user.username, session_type="meterpreter", parent=server_session)

        process = new_session.process
        process.ppid = session_to_persist.process.pid
        process.path = '/tmp/'  # NOTE: Change path to actual path...
        process.name = 'exploit.exe'
        local_port = session_to_persist.host.get_ephemeral_port()
        new_connection = {"Application Protocol": AppProtocol.TCP,
                          "remote_address": server_address,
                          "remote_port": 4433,
                          "local_address": persist_address,
                          "local_port": local_port}
        process.connections.append(new_connection)

        remote_port = {"local_port": 4433,
                       "Application Protocol": AppProtocol.TCP,
                       "local_address": server_address,
                       "remote_address": persist_address,
                       "remote_port": local_port
                       }
        server_session.process.connections.append(remote_port)

        obs.add_session_info(hostid=str(self.session_to_persist), session_id=new_session.ident,
                             session_type=new_session.session_type, agent=self.agent)

        obs.add_process(hostid=str(server_address), local_address=server_address, local_port=4433,
                        remote_address=persist_address,
                        remote_port=local_port)
        obs.add_process(hostid=str(self.session_to_persist), local_address=persist_address, local_port=local_port,
                        remote_address=server_address,
                        remote_port=4433,
                        process_name=process.name,
                        pid=process.pid)

        # Add persistence service to target host
        service_name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(5))
        session_to_persist.host.add_service(service_name=service_name, process=process, session=session_to_persist)

        return obs

    def emu_execute(self, session_handler):
        pass


    def __str__(self):
        return super(ServicePersistenceWindows, self).__str__() + f", Meterpreter Session: {self.session_to_persist}"