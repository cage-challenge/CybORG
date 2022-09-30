from math import sqrt

from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import ExploitDroneVulnerability, FloodBandwidth, SeizeControl, Sleep
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic


class RedDroneWormAgent(BaseAgent):
    def __init__(self, name, np_random=None):
        super().__init__(name, np_random)
        self.behaviour_type = self.np_random.randint(0, 6)
        self.chance_to_change = 0.1
        self.exploited_drones = []
        self.target_ip = None
        self.actions = [ExploitDroneVulnerability, FloodBandwidth, BlockTraffic]
        self.last_action = Sleep
        self.own_ip = None

    def get_action(self, observation, action_space):
        if self.own_ip is None:
            self.own_ip = observation['drone_'+self.name.split('_')[-1]]['Interface'][0]['IP Address']
        if self.np_random.random() < self.chance_to_change:
            self.behaviour_type = self.np_random.randint(0, 10)
        if self.behaviour_type == 0:
            # behaviour 0 is exploit as many drones as possible
            if self.target_ip is None or observation['success'] != True:
                # if not previously targetted a drone, target a new drone
                ip_list = [v['Interface'][0]['IP Address'] for k, v in observation.items() if k != 'success' and 'Interface' in v]
                if len(ip_list) > 0:
                    self.target_ip = self.np_random.choice(ip_list)
                    return ExploitDroneVulnerability(ip_address=self.target_ip, agent=self.name, session=0)
                else:
                    return Sleep()
            else:
                # else seize control of successfully exploited drone
                ip = self.target_ip
                self.target_ip = None
                return SeizeControl(ip_address=ip, agent=self.name, session=0)
        if self.behaviour_type == 1:
            # behaviour 1 is to attempt to flood drones that are as far away as possible
            locations = {v['Interface'][0]['IP Address']: v['System info']['position'] for k, v in
                         observation.items() if k != 'success' and 'System info' in v and 'position' in v['System info']}
            ip = self.own_ip
            if len(locations) > 0:
                own_pos = locations[ip]
                distance = 0
                for ip2, loc in locations.items():
                    dist2 = sqrt((own_pos[0]-loc[0])**2+(own_pos[1]-loc[1])**2)
                    if dist2 > distance:
                        distance = dist2
                        ip = ip2
            return FloodBandwidth(ip_address=ip, agent=self.name, session=0)
        if self.behaviour_type == 2:
            # behaviour 2 is to sleep any intercept any incoming data
            return Sleep()
        if self.behaviour_type == 3:
            # behaviour 3 is to exploit neighbouring drones
            if self.target_ip is None or observation['success'] != True:
                # if not previously targetted a drone, target a new drone
                locations = {v['Interface'][0]['IP Address']: v['System info']['position'] for k, v in
                             observation.items() if k != 'success' and 'System info' in v and 'position' in v['System info']}
                ip = self.own_ip
                if len(locations)>0:
                    own_pos = locations[ip]
                    distance = 0
                    for ip2, loc in locations.items():
                        dist2 = sqrt((own_pos[0] - loc[0]) ** 2 + (own_pos[1] - loc[1]) ** 2)
                        if dist2 > distance:
                            distance = dist2
                            ip = ip2
                    self.target_ip = ip
                    return ExploitDroneVulnerability(ip_address=self.target_ip, agent=self.name, session=0)
                else:
                    return Sleep()
            else:
                # else seize control of successfully exploited drone
                ip = self.target_ip
                self.target_ip = None
                return SeizeControl(ip_address=ip, agent=self.name, session=0)

        if self.behaviour_type == 4:
            # behaviour 4 is to randomly to flood drones
            ip_list = [v['Interface'][0]['IP Address'] for k, v in observation.items() if
                       k != 'success' and 'Interface' in v]
            if len(ip_list) > 0:
                ip = self.np_random.choice(ip_list)
                return FloodBandwidth(ip_address=ip, agent=self.name, session=0)
            else:
                return Sleep()
        if self.behaviour_type == 5:
            # behaviour 5 is to block random drones
            ip_list = [v['Interface'][0]['IP Address'] for k, v in observation.items() if
                       k != 'success' and 'Interface' in v]
            if len(ip_list) > 0:
                ip = self.np_random.choice(ip_list)
                return BlockTraffic(ip_address=ip, agent=self.name, session=0)
            else:
                return Sleep()
        # just in case choose new behaviour and sleep
        self.behaviour_type = self.np_random.randint(0, 6)
        return Sleep()

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def end_episode(self):
        """Allows an agent to update its internal state"""
        self.__init__(self.name, self.np_random)

    def set_initial_values(self, action_space, observation):
        pass