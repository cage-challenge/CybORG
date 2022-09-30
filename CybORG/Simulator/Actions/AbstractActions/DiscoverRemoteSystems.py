from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.Pingsweep import Pingsweep


class DiscoverRemoteSystems(Action):
    """
    High level action that discovers active ip addresses on a subnet.

    Calls the low level action Pingsweep.
    """
    def __init__(self, subnet: IPv4Network, session: int, agent: str):
        super().__init__()
        self.subnet = subnet
        self.agent = agent
        self.session = session

    def execute(self, state) -> Observation:
        # find session inside or close to the target subnet
        session = self.session
        # run pingsweep on the target subnet from selected session
        sub_action = Pingsweep(session=self.session, agent=self.agent, subnet=self.subnet)
        obs = sub_action.execute(state)
        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.subnet}"

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        equality_tuple = (
                self.name == other.name, 
                self.subnet == other.subnet,
                self.agent == other.agent,
                self.session == other.session,
                )

        return all(equality_tuple)
