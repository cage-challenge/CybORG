import numpy as np
from gym import spaces

from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper


class ActionsCommsPettingZooParallelWrapper(PettingZooParallelWrapper):
    """Communicates the action selection to other agents"""

    def __init__(self, env):
        super(ActionsCommsPettingZooParallelWrapper, self).__init__(env)
        self.num_drones = len(self.ip_addresses)
        self._observation_spaces = {agent_name: spaces.MultiDiscrete(
            [3] + [2 for i in range(self.num_drones)] + [2] + [3 for i in range(self.num_drones)] + [101, 101] + (
                    self.num_drones - 1) * [self.num_drones, 101, 101, 2] + self.num_drones*[self.action_space(agent_name).n+1]) for agent_name in self.possible_agents}
        self.msg_len = self.num_drones
        self.encoding = {agent: {i: [int(x) for x in bin(i)[2:].zfill(self.env.get_message_space(agent).n)] for i in range(self.action_space(agent).n)} for agent in self.env.agents}
        self.decoding = {agent: {str(v): k for k, v in self.encoding[agent].items()} for agent in self.env.agents}

    def parse_message(self, message: list, agent_name: str):
        new_message = [1+self.decoding[agent_name][str(i)] for i in message if str(i) in self.decoding[agent_name]]
        while len(new_message) < self.num_drones:
            new_message.append(0)
        return new_message

    def select_messages(self, action):
        return action, {agent: self.encoding[agent][act] for agent, act in action.items()}


class ObsCommsPettingZooParallelWrapper(PettingZooParallelWrapper):
    """Communicates part of the previous observation to other agents"""

    def __init__(self, env):
        super(ObsCommsPettingZooParallelWrapper, self).__init__(env)
        self.num_drones = len(self.ip_addresses)
        self._observation_spaces = {agent_name: spaces.MultiDiscrete(
            [3] + [2 for i in range(self.num_drones)] + [2] + [3 for i in range(self.num_drones)] + [101, 101] + (
                    self.num_drones - 1) * [self.num_drones, 101, 101, 2] + [2 for _ in range(self.env.get_message_space('blue_agent_0').n)]*self.num_drones) for agent_name in self.possible_agents}
        self.msg_len = self.num_drones * self.env.get_message_space('blue_agent_0').n

    def parse_message(self, message: list, agent_name: str):
        new_message = message
        while len(new_message) < self.num_drones:
            new_message.append([0 for _ in range(self.env.get_message_space(agent_name).n)])
        return np.array(new_message).flatten()

    def select_messages(self, action):
        msg = {}
        for agent in action.keys():
            obs = self.env.get_observation(agent)

            msg[agent] = [self.get_data_from_obs(obs, i) for i in range(self.env.get_message_space(agent).n)]
        return action, {agent: msg[agent] for agent, act in action.items()}

    @staticmethod
    def get_data_from_obs(obs, i):
        """Example obs
        {'success': <TrinaryEnum.UNKNOWN: 2>,
        'drone_0':
            {'Interface': [{'Interface Name': 'wlan0', 'IP Address': IPv4Address('10.0.119.225'), 'Subnet': IPv4Network('10.0.119.224/28')}],
            'Sessions': [{'Username': 'root', 'ID': 0, 'Timeout': 0, 'PID': 26612, 'Type': <SessionType.BLUE_DRONE_SESSION: 13>, 'Agent': 'blue_agent_0'}],
            'Processes': [{'PID': 26612, 'Username': 'root'}],
            'User Info': [{'Username': 'root', 'Groups': [{'GID': 0}]}, {'Username': 'drone_user', 'Groups': [{'GID': 0}]}],
            'System info': {'Hostname': 'drone_0', 'OSType': <OperatingSystemType.LINUX: 3>, 'OSDistribution': <OperatingSystemDistribution.DRONE_LINUX: 15>, 'OSVersion': <OperatingSystemVersion.UNKNOWN: 1>, 'Architecture': <Architecture.UNKNOWN: 3>, 'position': array([22.0000052 , 78.00322484])}},
        'drone_1':
            {'Interface': [{'Interface Name': 'wlan0', 'IP Address': IPv4Address('10.0.119.233'), 'Subnet': IPv4Network('10.0.119.224/28')}],
            'System info': {'Hostname': 'drone_1', 'OSType': <OperatingSystemType.LINUX: 3>, 'OSDistribution': <OperatingSystemDistribution.DRONE_LINUX: 15>, 'OSVersion': <OperatingSystemVersion.UNKNOWN: 1>, 'Architecture': <Architecture.UNKNOWN: 3>, 'position': array([92.05532861, 41.0015318 ])}}, etc """
        num_drones = len([i for i in obs.keys() if 'drone' in i])
        if i >= num_drones * 2:
            return 0
        else:
            drone_data = obs.get(f'drone_{i % num_drones}')
            # first send if you found malicious traffic from that drone
            if i < num_drones:
                return 1 if any(['Network Connections' in drone_data['Interface']]) else 0
            # next send if you are blocking any traffic to specific hosts
            if i < 2 * num_drones:
                return 1 if any(['blocked_ips' in drone_data['Interface']]) else 0


class AgentCommsPettingZooParallelWrapper(PettingZooParallelWrapper):
    """Allows agents to select their action"""
    def __init__(self, env):
        super(AgentCommsPettingZooParallelWrapper, self).__init__(env)
        num_drones = len(self.ip_addresses)
        self.len_actions = {agent: self.action_space(agent).n for agent in self.possible_agents}
        self._action_spaces = {agent: spaces.Discrete(self.len_actions[agent]*self.env.get_message_space(agent).n)
                               for agent in self.possible_agents}
        # success + own_drone(block Ips + processes + network conns + pos) + other_drones(IPs + session_+pos)
        self._observation_spaces = {agent_name: spaces.MultiDiscrete(
            [3] + [2 for i in range(num_drones)] + [2] + [3 for i in range(num_drones)] + [101, 101] + (
                    num_drones - 1) * [num_drones, 101, 101, 2] + num_drones*[self.action_space(agent_name).n+1]) for agent_name in self.possible_agents}
        self.msg_len = num_drones

        self.encoding = {agent: {i: [int(x) for x in bin(i)[2:].zfill(self.env.get_message_space(agent).n)] for i in
                                 range(self.env.get_message_space(agent).n)} for agent in self.env.agents}

        self.decoding = {agent: {str(v): k for k, v in self.encoding[agent].items()} for agent in self.env.agents}

    def parse_message(self, message: list, agent_name: str):
        new_message = [1+self.decoding[agent_name][str(i)] for i in message if str(i) in self.decoding[agent_name]]
        while len(new_message) < len(self.ip_addresses):
            new_message.append(0)
        return new_message

    def select_messages(self, action):
        return {agent: act%self.len_actions[agent] for agent, act in action.items()}, {agent: self.encoding[agent][act//self.len_actions[agent]] for agent, act in action.items()}
