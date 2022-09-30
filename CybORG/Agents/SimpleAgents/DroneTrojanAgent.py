from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import Sleep
from CybORG.Simulator.Actions.ConcreteActions.ActivateTrojan import ActivateTrojan


class DroneTrojanAgent(BaseAgent):
    """Agent that controls the behaviour of the hardware trojan"""
    def __init__(self, num_drones: int, name: str, np_random=None, spawn_rate=0.1):
        super().__init__(np_random)
        self.spawn_rate = spawn_rate
        self.num_drones = num_drones
        self.name = name

    def train(self, results: Results):
        pass

    def get_action(self, observation, action_space):
        # TODO use poisson distribution
        if self.np_random.random() < self.spawn_rate:
            return ActivateTrojan(hostname=f'drone_{self.np_random.randint(0, self.num_drones-1)}', agent=self.name)
        else:
            return Sleep()

    def end_episode(self):
        pass

    def set_initial_values(self, action_space, observation):
        pass
