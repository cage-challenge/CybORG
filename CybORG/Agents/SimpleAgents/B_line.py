import random

from CybORG.Agents import BaseAgent
from CybORG.Shared import Results
from CybORG.Shared.Actions import PrivilegeEscalate, ExploitRemoteService, DiscoverRemoteSystems, Impact, \
    DiscoverNetworkServices, Sleep


class B_lineAgent(BaseAgent):
    def __init__(self):
        self.action = 0
        self.target_ip_address = None
        self.last_subnet = None
        self.last_ip_address = None
        self.action_history = {}
        self.jumps = [0,1,2,2,2,2,5,5,5,5,9,9,9,12,13]

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def get_action(self, observation, action_space):
        # print(self.action)
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        session = 0

        while True:
            if observation['success'] == True:
                self.action += 1 if self.action < 14 else 0
            else:
                self.action = self.jumps[self.action]

            if self.action in self.action_history:
                action = self.action_history[self.action]

            # Discover Remote Systems
            elif self.action == 0:
                self.initial_ip = observation['User0']['Interface'][0]['IP Address']
                self.last_subnet = observation['User0']['Interface'][0]['Subnet']
                action = DiscoverRemoteSystems(session=session, agent='Red', subnet=self.last_subnet)
            # Discover Network Services- new IP address found
            elif self.action == 1:
                hosts = [value for key, value in observation.items() if key != 'success']
                get_ip = lambda x : x['Interface'][0]['IP Address']
                interfaces = [get_ip(x) for x in hosts if get_ip(x)!= self.initial_ip]
                self.last_ip_address = random.choice(interfaces)
                action =DiscoverNetworkServices(session=session, agent='Red', ip_address=self.last_ip_address)

            # Exploit User1
            elif self.action == 2:
                 action = ExploitRemoteService(session=session, agent='Red', ip_address=self.last_ip_address)

            # Privilege escalation on User Host
            elif self.action == 3:
                hostname = [value for key, value in observation.items() if key != 'success' and 'System info' in value][0]['System info']['Hostname']
                action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)

            # Discover Network Services- new IP address found
            elif self.action == 4:
                self.enterprise_host = [x for x in observation if 'Enterprise' in x][0]
                self.last_ip_address = observation[self.enterprise_host]['Interface'][0]['IP Address']
                action = DiscoverNetworkServices(session=session, agent='Red', ip_address=self.last_ip_address)

            # Exploit- Enterprise Host
            elif self.action == 5:
                self.target_ip_address = [value for key, value in observation.items() if key != 'success'][0]['Interface'][0]['IP Address']
                action = ExploitRemoteService(session=session, agent='Red', ip_address=self.target_ip_address)

            # Privilege escalation on Enterprise Host
            elif self.action == 6:
                hostname = [value for key, value in observation.items() if key != 'success' and 'System info' in value][0]['System info']['Hostname']
                action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)

            # Scanning the new subnet found.
            elif self.action == 7:
                self.last_subnet = observation[self.enterprise_host]['Interface'][0]['Subnet']
                action = DiscoverRemoteSystems(subnet=self.last_subnet, agent='Red', session=session)

            # Discover Network Services- Enterprise2
            elif self.action == 8:
                self.target_ip_address = [value for key, value in observation.items() if key != 'success'][2]['Interface'][0]['IP Address']
                action = DiscoverNetworkServices(session=session, agent='Red', ip_address=self.target_ip_address)

            # Exploit- Enterprise2
            elif self.action == 9:
                self.target_ip_address = [value for key, value in observation.items() if key != 'success'][0]['Interface'][0]['IP Address']
                action = ExploitRemoteService(session=session, agent='Red', ip_address=self.target_ip_address)

            # Privilege escalation on Enterprise2
            elif self.action == 10:
                hostname = [value for key, value in observation.items() if key != 'success' and 'System info' in value][0]['System info']['Hostname']
                action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)

            # Discover Network Services- Op_Server0
            elif self.action == 11:
                action = DiscoverNetworkServices(session=session, agent='Red', ip_address=observation['Op_Server0']['Interface'][0]['IP Address'])

            # Exploit- Op_Server0
            elif self.action == 12:
                info = [value for key, value in observation.items() if key != 'success']
                if len(info) > 0:
                    action = ExploitRemoteService(agent='Red', session=session, ip_address=info[0]['Interface'][0]['IP Address'])
                else:
                    self.action = 0
                    continue
            # Privilege escalation on Op_Server0
            elif self.action == 13:
                action = PrivilegeEscalate(agent='Red', hostname='Op_Server0', session=session)
            # Impact on Op_server0
            elif self.action == 14:
                action = Impact(agent='Red', session=session, hostname='Op_Server0')

            if self.action not in self.action_history:
                self.action_history[self.action] = action
            return action

    def end_episode(self):
        self.action = 0
        self.target_ip_address = None
        self.last_subnet = None
        self.last_ip_address = None
        self.action_history = {}

    def set_initial_values(self, action_space, observation):
        pass
