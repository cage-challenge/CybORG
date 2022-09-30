# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Shared.Actions.MSFActionsFolder.MSFScannerFolder.MSFScanner import MSFScanner
from CybORG.Shared.Enums import InterfaceType, SessionType, ProcessType, ProcessVersion, AppProtocol
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# msf module is auxiliary/scanner/http/tomcat_mgr_login - then set RHOSTS and RPORT
class TomcatCredentialScanner(MSFScanner):
    def __init__(self, ip_address: IPv4Address, port: int, session: int, agent: str):
        super().__init__(session, agent)
        self.target = ip_address
        self.target_port = port

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        from_host = state.sessions['Red'][self.session].host
        session = state.sessions['Red'][self.session]

        good = False
        if session.session_type == SessionType.MSF_SERVER and session.active:
            good = True

        if not good:
            obs.set_success(False)
            return obs

        session, from_interface = self.get_local_source_interface(local_session=session, remote_address=self.target)

        if from_interface is None:
            obs.set_success(False)
            return obs

        if str(self.target) == "127.0.0.1":
            target_host = from_host
        else:
            target_host = state.hosts[state.ip_addresses[self.target]]

        target_proc = None
        for process in target_host.processes:
            for conn in process.connections:
                if self.target_port == conn['local_port']:
                    if conn['local_address'] == IPv4Address("0.0.0.0") or (conn['local_address'] == IPv4Address("127.0.0.1") and self.target == IPv4Address("127.0.0.1")) or conn['local_address'] == self.target:
                        target_proc = process
                    break

        if target_proc is None:
            obs.set_success(False)
            return obs
        else:
            if target_proc.process_type == ProcessType.WEBSERVER:
                if target_proc.version == ProcessVersion.APACHE_TOMCAT:
                    for conn in target_proc.connections:
                        if conn["local_port"] == self.target_port:
                            if conn['Application Protocol'] == AppProtocol.HTTP:
                                obs.set_success(True)
                                obs.add_process(hostid="hostid0", local_address=self.target, local_port=self.target_port,
                                                app_protocol="TCP", process_type=target_proc.process_type,
                                                process_version=target_proc.version, status="open")
                                obs.add_user_info(hostid="hostid0", username="tomcat", password="tomcat", group_name="web server users")
                            else:
                                obs.set_success(False)
                                obs.add_process(hostid="hostid0", local_address=self.target, local_port=self.target_port,
                                                app_protocol="TCP", process_type=target_proc.process_type, status="open")
                else:
                    obs.set_success(False)
                    obs.add_process(hostid="hostid0", local_address=self.target, local_port=self.target_port,
                                    app_protocol="TCP", process_type=target_proc.process_type, status="open")
            else:
                obs.set_success(False)
        return obs

    def emu_execute(self, session_handler) -> Observation:
        obs = Observation()
        from CybORG.Emulator.Session import MSFSessionHandler
        if type(session_handler) is not MSFSessionHandler:
            obs.set_success(False)
            return obs
        output = session_handler.execute_module(mtype='auxiliary', mname='scanner/http/tomcat_mgr_login',
                                         opts={'RHOSTS': str(self.target),
                                               'RPORT': self.target_port})
        obs.add_raw_obs(output)
        obs.set_success(False)
        return obs