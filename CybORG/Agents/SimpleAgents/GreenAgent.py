from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import Sleep, GreenPingSweep, GreenPortScan, GreenConnection

class GreenAgent(BaseAgent):
    def __init__(self, np_random=None):
        super().__init__(np_random)
        self.action_space = [
                Sleep,
                # GreenPingSweep,
                GreenPortScan,
                # GreenConnection, 
                ]
        self.hostnames = [
                'User0',
                'User1',
                'User2',
                'User3',
                'User4',
                'Enterprise0',
                'Enterprise1',
                'Enterprise2',
                ]
        self.subnets = [
                'User',
                'Enterprise',
                'Operational_A',
                ]

    def get_action(self,observation,action_space):
        action = self.np_random.choice(self.action_space)
        if action == Sleep:
            return Sleep()
        elif action == GreenPingSweep:
            subnet = self.np_random.choice(self.subnets)
            return action(subnet=subnet,session=0,agent='Green')
        else:
            hostname = self.np_random.choice(self.hostnames)
            return action(hostname=hostname,session=0,agent='Green')

    def train(self,results):
        pass

    def end_episode(self):
        pass

    def set_initial_values(self,action_space,observation):
        pass
