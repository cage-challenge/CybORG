from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl

class RemoveBlueDrone(BaseAgent):
    def __init__(self, name):
        super().__init__(name)

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        action=RemoveOtherSessions(agent=self.name, session=0)
        return action

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name)

    def set_initial_values(self, action_space, observation):
        pass

class RetakeBlueDrone(BaseAgent):
    def __init__(self, name):
        super().__init__(name)
        self.initial_obs = True
        self.ip_list = []

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        if self.initial_obs:
            self.ip_list = [v['Interface'][0]['IP Address'] \
                    for k, v in observation.items() if k!= 'success']
            self.initial_obs = False
        
        target_ip = self.np_random.choice(self.ip_list)
        
        action = RetakeControl(agent=self.name, session=0, ip_address=target_ip)
        return action

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name)

    def set_initial_values(self, action_space, observation):
        pass


class AdvancedRetakeBlueDrone(BaseAgent):
    def __init__(self, name):
        super().__init__(name)
        self.initial_obs = True
        self.sus_ips = []
        self.target_ip = None

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        if self.target_ip is not None and observation['success'] == True:
                self.sus_ips.remove(self.target_ip)
        self.target_ip = None

        new_sus_ips = [ip['remote_address'] for k, v in observation.items() if k != 'success' and 'NetworkConnections' in v['Interface'][0] for ip in v['Interface'][0]['NetworkConnections']]
        for sus_ip in new_sus_ips:
            if sus_ip not in self.sus_ips:
                self.sus_ips.append(sus_ip)
        malware_detected = [k for k, v in observation.items() if k != 'success' and 'Processes' in v]
        if len(malware_detected) == 0 and len(self.sus_ips) > 0:
            self.target_ip = self.np_random.choice(self.sus_ips)
            action = RetakeControl(agent=self.name, session=0, ip_address=self.target_ip)
            return action
        return RemoveOtherSessions(agent=self.name, session=0)

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name)

    def set_initial_values(self, action_space, observation):
        pass

class AdvancedBlockBlueDrone(BaseAgent):
    def __init__(self, name):
        super().__init__(name)
        self.initial_obs = True
        self.sus_ips = []
        self.target_ip = None

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        if self.target_ip is not None and observation['success'] == True:
                self.sus_ips.remove(self.target_ip)
        self.target_ip = None

        new_sus_ips = [ip['remote_address'] for k, v in observation.items() if k != 'success' and 'NetworkConnections' in v['Interface'][0] for ip in v['Interface'][0]['NetworkConnections']]
        for sus_ip in new_sus_ips:
            if sus_ip not in self.sus_ips:
                self.sus_ips.append(sus_ip)
        if len(self.sus_ips) > 0:
            self.target_ip = self.np_random.choice(self.sus_ips)
            action = BlockTraffic(agent=self.name, session=0, ip_address=self.target_ip)
            return action
        return RemoveOtherSessions(agent=self.name, session=0)

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name)

    def set_initial_values(self, action_space, observation):
        pass
