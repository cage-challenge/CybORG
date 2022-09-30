from copy import deepcopy

import numpy as np
from gym import spaces, Env

from CybORG.Agents.Utils import RedAgentBelief, HostStatus
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Simulator.Actions import Sleep

class SimpleRedWrapper(BaseWrapper, Env):
    def __init__(self, env=None, step_limit=100):
        super().__init__(env)
        self.agent_name = 'Red'
        self.belief = RedAgentBelief()
        self.current_step = 0
        self.step_limit = step_limit
        self.last_action = None
        self.history = []

        self.ip_map = self.env.get_ip_map()
        self.host_list = sorted(list(self.ip_map.keys()))
        self.action_space = spaces.Discrete(len(self.host_list))
        obs_size = len(self.host_list) + 2
        self.observation_space = spaces.Box(low=-2, high=5, shape=(obs_size,))

    def reset(self, agent=None):
        self.belief.clear()
        self.current_step = 0
        self.last_action = None
        self.history = []

        result = self.env.reset(agent)
        self.belief.update(result.observation, None)

        self.ip_map = self.env.get_ip_map()
        self.host_list = list(self.ip_map.keys())
        self.action_space = spaces.Discrete(len(self.host_list))
        
        return self.get_observation()

    def step(self, action: int=None):
        cyborg_action = self.get_cyborg_action(action)
        self.last_action = cyborg_action
        self.history.append(cyborg_action)

        target_ip = self._get_target_ip(cyborg_action)
        target_status = deepcopy(self.belief.hosts[target_ip].status.value) \
                if target_ip is not None else None

        results = self.env.step(action=cyborg_action, agent='Red')
        self.belief.update(results.observation, cyborg_action)

        obs = self.get_observation()
        success = results.observation['success']
        impact_ready = obs[-1]
        reward = self.reward_shape(success, target_ip, target_status, impact_ready)
        done = self.compute_done(impact_ready)

        self.current_step += 1

        return obs, reward, done, {'true_reward': results.reward}

    def get_cyborg_action(self, action: int):
        action = int(action)
        if action not in self.action_space:
            raise ValueError('SimpleRedWrapper: Action input must be in range!')

        unscanned_subnets = self.belief.unscanned_subnets
        if len(unscanned_subnets) > 0:
            target_subnet = unscanned_subnets[0]
            cyborg_action = self.belief.subnets[str(target_subnet)].next_action
            return cyborg_action

        hostname = self.host_list[action]
        target_ip = self.ip_map[hostname]
        host_belief = self.belief.hosts.get(str(target_ip))
        cyborg_action = Sleep() if host_belief is None else host_belief.next_action

        return cyborg_action

    def _get_target_ip(self, action):
        if action.name in ('Impact', 'PrivilegeEscalate'):
            return str(self.ip_map[action.hostname])
        elif action.name in ('ExploitRemoteService', 'DiscoverNetworkServices'):
            return str(action.ip_address)
        else:
            return None

    def get_observation(self):
        '''
        Returns observation vector. First entry is binary number representing whether 
        there are unscanned subnets. Subsequent entries are status values for each host.
        '''
        unscanned_subnets = self.belief.unscanned_subnets
        has_unscanned_subnets = 1 if len(unscanned_subnets) > 0 else 0
        proto_vector = [has_unscanned_subnets]

        beliefs = [self.belief.hosts.get(str(ip)) for ip in self.ip_map.values()]
        get_status = lambda x: -1 if x is None else x.status.value
        status_vector = [get_status(x) for x in beliefs]
        proto_vector.extend(status_vector)

        opserver_ip = self.ip_map['Op_Server0']
        opserver_belief = self.belief.hosts.get(str(opserver_ip))
        opserver_status = opserver_belief.status.value if opserver_belief is not None \
                else 0
        impact_ready = 1 if opserver_status >= 3 else 0
        proto_vector.append(impact_ready)

        return np.array(proto_vector)

    def vector_to_observation(self, vector):
        vector = list(vector)
        subnet_status = 'No Unscanned Subnets' if vector[0] == 0 \
                else 'Unscanned Subnets Exist'
        
        keys = self.ip_map.keys()
        values = [HostStatus(v).name for v in vector[1:]]
        host_state = dict(zip(keys, values))

        return {'subnet_status': subnet_status, 'host_state': host_state}

    def reward_shape(self, success, target_ip, old_status, impact_ready):
        if success == False:
            return -0.1
        # elif impact_ready:
            # return 10

        action = self.belief.last_action
        if action.name == 'Impact':
            return 10
        elif action.name == 'Sleep':
            return -0.1
        elif action.name == 'DiscoverRemoteSystems':
            return 0
        elif target_ip is None:
            raise NotImplementedError('SimpleRedWrapper has target_ip == None, \
                    but action is not DiscoverRemoteSystems')

        new_status = self.belief.hosts[target_ip].status.value
        if new_status - old_status > 0:
            return 1

        return 0
            
    def compute_done(self, impact_ready):
        if self.current_step == self.step_limit:
            return True
        # elif impact_ready == 1:
            # return True

        return False
