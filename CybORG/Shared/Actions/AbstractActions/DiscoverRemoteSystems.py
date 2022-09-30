from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Shared.Actions import Action
from CybORG.Shared.Actions.ConcreteActions.Pingsweep import Pingsweep


class DiscoverRemoteSystems(Action):
    """
    High level action that discovers active ip addresses on a subnet.

    Calls the low level action Pingsweep.
    """
    def __init__(self, session: int, agent: str, subnet: IPv4Network):
        super().__init__()
        self.subnet = subnet
        self.agent = agent
        self.session = session

    def sim_execute(self, state) -> Observation:
        # find session inside or close to the target subnet
        session = self.session
        # run pingsweep on the target subnet from selected session
        sub_action = Pingsweep(session=self.session, agent=self.agent, subnet=self.subnet, target_session=session)
        obs = sub_action.sim_execute(state)
        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.subnet}"
