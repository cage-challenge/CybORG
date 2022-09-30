# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Shared.Actions.ShellActionsFolder.OpenConnectionFolder.OpenConnection import OpenConnection
from CybORG.Shared.Enums import ProcessType, InterfaceType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# smbclient -L //target -N
class SMBAnonymousConnection(OpenConnection):
    def __init__(self, ip_address: IPv4Address, session: int, agent: str):
        super().__init__(session=session, agent=agent)
        self.target = ip_address

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if not session.active or self.target not in state.ip_addresses:
            return obs

        # check if smbclient is on session's dict
        client = False
        for file in session.host.files:
            if file.name == "smbclient" and file.check_executable(session.user):
                client = True

        if not client:
            return obs

        # check if ip is on same subnet as dict of session
        shared_subnet = False
        for interface in session.host.interfaces:
            if interface.ip_address != IPv4Address("127.0.0.1") and self.target in interface.subnet.ip_addresses:
                shared_subnet = True
                break

        if not shared_subnet:
            return obs

        smb_proc = None
        for proc in state.hosts[state.ip_addresses[self.target]].processes:
            if proc.process_type == ProcessType.SMB:
                smb_proc = proc
                break

        if smb_proc is not None:
            for conn in smb_proc.connections:
                if conn['local_address'] == IPv4Address("0.0.0.0"):
                    obs.set_success(True)
                    obs.add_process(local_address=str(self.target), status="open", process_type="smb",
                                    process_version=smb_proc.version)
                    break
        else:
            obs.add_interface_info(ip_address=str(self.target))

        return obs
        # what else to check as far as obs is affected?
        # do we change the state at all? Might create an event that blue can see
