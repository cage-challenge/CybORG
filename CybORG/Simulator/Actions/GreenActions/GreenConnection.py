from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.BlueKeep import BlueKeep
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.EternalBlue import EternalBlue
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.HTTPRFI import HTTPRFI
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.HTTPSRFI import HTTPSRFI
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.SSHBruteForce import SSHBruteForce
from CybORG.Simulator.Actions.Action import lo
from CybORG.Simulator.Session import GreenAbstractSession
from CybORG.Simulator.State import State


class GreenConnection(Action):
    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__()
        self.hostname = hostname
        self.agent = agent
        self.session = session

    def execute(self, state: State) -> Observation:
        # find session inside or close to the target subnet
        session = self.session
        # Find ip address of host
        ip_map = state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == self.hostname:
                self.ip_address = ip
                break

        if type(state.sessions[self.agent][self.session]) is GreenAbstractSession and self.ip_address in state.sessions[self.agent][self.session].ports:
            ports = state.sessions[self.agent][self.session].ports[self.ip_address]
            exploit_options = {EternalBlue: 2.0 if 139 in ports else 0.0,
                               BlueKeep: 1.0 if 3389 in ports else 0.0,
                               HTTPRFI: 3.0 if 80 in ports else 0.0,
                               HTTPSRFI: 4.0 if 443 in ports else 0.0,
                               SSHBruteForce: 0.1 if 22 in ports else 0.0}
            # use information to populate weights for which exploit to select

            # sample the exploit to perform from the exploit weights
            sub_action = list(exploit_options.keys())[
                list(exploit_options.values()).index(max(list(exploit_options.values())))](session=self.session,
                                                                                           agent=self.agent,
                                                                                           ip_address=self.ip_address,
                                                                                           target_session=session)
            obs = sub_action.execute(state)
            if self.ip_address != lo and obs.data['success'] == True:
                hostname = obs.data[str(self.ip_address)]["System info"]["Hostname"]
                os = obs.data[str(self.ip_address)]["System info"]["OSType"]
                state.sessions[self.agent][self.session].addos(hostname, os)
        else:
            obs = Observation(success=False)
        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.ip_address}"
