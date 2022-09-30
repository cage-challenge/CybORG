# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.PersistenceFolder.Persistence import Persistence
from CybORG.Simulator.State import State
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.Observation import Observation

class Schtasks(Persistence):
    def __init__(self, session, agent, frequency, ip_address):
        super().__init__(session, agent)
        self.callback_ip = ip_address
        self.step_installed = 0
        self.frequency = frequency

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        if not state.sessions[self.agent][self.session].active:
            return obs

        host = state.sessions[self.agent][self.session].host
        obs.add_system_info(hostid="hostid0", os_type=host.os_type)
        host.add_scheduled_task(self)
        obs.set_success(True)
        self.step_installed = state.step
        return obs

    def scheduled_task(self, step):
        if (step - self.step_installed) % self.frequency == 0:
            # SSH CONNECTION TO self.callback_ip
            pass
