from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import Sleep
from CybORG.Simulator.Actions.GreenActions.SendData import SendData


class GreenDroneAgent(BaseAgent):
    def __init__(self, name, own_ip):
        super().__init__(name)
        self.own_ip = own_ip
        self.target_ip = None
        self.num_steps_left = 0
        self.chance_to_act = 1.
        self.minimum_bandwidth = 1
        self.maximum_bandwidth = 3

    def train(self, results: Results):
        pass

    def get_action(self, observation, action_space):
        #
        # if self.num_steps_left > 0:
        #     self.num_steps_left -= 1
        bandwidth_usage = 1
        ip_address = self.np_random.choice([i for i in action_space['ip_address'] if i != self.own_ip])
        return SendData(agent=self.name, session=0, ip_address=ip_address, bandwidth_usage=bandwidth_usage)

    def end_episode(self):
        self.target_ip = None
        self.num_steps_left = 0

    def set_initial_values(self, action_space, observation):
        pass
