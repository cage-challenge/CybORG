from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import ExploitDroneVulnerability, FloodBandwidth, SeizeControl, Sleep
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic


class DroneRedAgent(BaseAgent):
    def __init__(self, name, np_random = None):
        super().__init__(name, np_random)
        self.initial_obs = True
        self.ip_list = []
        self.actions = [ExploitDroneVulnerability, SeizeControl]
        self.last_ip = None

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        if self.initial_obs:
            self.ip_list = [v['Interface'][0]['IP Address'] \
                    for k, v in observation.items() if k!= 'success']
            self.initial_obs = False
        # if self.np_random.random() < 0.5:
        if self.last_ip is None:
            self.last_ip = self.np_random.choice(self.ip_list)
            return ExploitDroneVulnerability(ip_address=self.last_ip, agent=self.name, session=0)
        else:
            last_ip = self.last_ip
            self.last_ip = None
            return SeizeControl(ip_address=last_ip, agent=self.name, session=0)

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name, self.np_random)

    def set_initial_values(self, action_space, observation):
        pass


class LegalExploitDrone(BaseAgent):
    def __init__(self, name, np_random=None):
        super().__init__(name, np_random)
        self.initial_obs = True
        self.ip_list = []
        self.actions = [ExploitDroneVulnerability, FloodBandwidth, BlockTraffic]
        self.last_action = Sleep
        self.target_ip = None

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        if type(self.last_action) is ExploitDroneVulnerability and observation['success'] == True:
            self.last_action = SeizeControl
        else:
            ip_list = [v['Interface'][0]['IP Address'] for k, v in observation.items() if k != 'success']
            if len(ip_list) > 0:
                self.target_ip = self.np_random.choice(ip_list)
                self.last_action = self.np_random.choice(self.actions)
            else:
                self.last_action = Sleep
                return self.last_action()

        return self.last_action(ip_address=self.target_ip, agent=self.name, session=0)

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name, self.np_random)

    def set_initial_values(self, action_space, observation):
        pass


class FloodAgent(BaseAgent):
    def get_action(self, observation, action_space):
        return FloodBandwidth(session=0, agent=self.name, ip_address=self.np_random.choice([i for i, v in action_space['ip_address'].items() if v]))
    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass
    def end_episode(self):
        """Allows an agent to update its internal state"""
        pass
    def set_initial_values(self, action_space, observation):
        pass

class BlockAgent(BaseAgent):
    def get_action(self, observation, action_space):
        return BlockTraffic(session=0, agent=self.name, ip_address=self.np_random.choice([i for i, v in action_space['ip_address'].items() if v]))
    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass
    def end_episode(self):
        """Allows an agent to update its internal state"""
        pass
    def set_initial_values(self, action_space, observation):
        pass

