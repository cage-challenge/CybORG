from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.Portscan import Portscan


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

    def execute(self, state) -> Observation:
        # find session inside or close to the target subnet
        session = self.session
        # run portscan on the target ip address from the selected session
        sub_action = Portscan(session=self.session, agent=self.agent, ip_address=self.ip_address)
        obs = sub_action.execute(state)
        if str(self.ip_address) in obs.data:
            state.sessions[self.agent][self.session].clearports(self.ip_address)
            for proc in obs.data[str(self.ip_address)]["Processes"]:
                for conn in proc['Connections']:
                    port = conn["local_port"]
                    state.sessions[self.agent][self.session].addport(self.ip_address, port)

        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.ip_address}"

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        equality_tuple = (
                self.name == other.name,
                self.ip_address == other.ip_address,
                self.agent == other.agent,
                self.session == other.session,
                )

        return all(equality_tuple)
