from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.Pingsweep import Pingsweep


class GreenPingSweep(Action):
    def __init__(self, session: int, agent: str, subnet: IPv4Network):
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
