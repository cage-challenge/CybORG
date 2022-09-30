from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Shared.Actions import Action
from CybORG.Shared.Actions.ConcreteActions.Portscan import Portscan


class DiscoverNetworkServices(Action):
    """
    High Level Action that allows an agent to identify services on a host as a prerequisite for running an exploit.

    Calls the low level action PortScan then modifies the observation. Must be used on a host to
    successfully run the high level action ExploitRemoteServices.
    """
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super().__init__()
        self.ip_address = ip_address
        self.agent = agent
        self.session = session

    def sim_execute(self, state) -> Observation:
        # find session inside or close to the target subnet
        session = self.session
        # run portscan on the target ip address from the selected session
        sub_action = Portscan(session=self.session, agent=self.agent, ip_address=self.ip_address, target_session=session)
        obs = sub_action.sim_execute(state)
        if str(self.ip_address) in obs.data:
            state.sessions[self.agent][self.session].clearports(self.ip_address)
            for proc in obs.data[str(self.ip_address)]["Processes"]:
                for conn in proc['Connections']:
                    port = conn["local_port"]
                    state.sessions[self.agent][self.session].addport(self.ip_address, port)

        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.ip_address}"
