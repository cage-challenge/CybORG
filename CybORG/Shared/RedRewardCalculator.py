# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Scenario
from CybORG.Shared.Actions import FindFlag, Impact
from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.RewardCalculator import RewardCalculator

WIN_REWARD = 0
LOSE_REWARD = 0
SESSION_REWARD = 0
ROOT_SESSION_REWARD = 0
LOSE_SESSION_REWARD = 0
LOSE_ROOT_SESSION_REWARD = 0

REWARD_MAX_DECIMAL_PLACES = 1


class PwnRewardCalculator(RewardCalculator):
    # this reward calculator provides a reward to Red due to changes in the number of privileged sessions
    def __init__(self, agent_name: str, scenario: Scenario):
        super().__init__(agent_name)
        self.old_total = 0
        self.scenario = scenario
        self.mapping = {'None': 0.0,
                        'Low': 0.1,
                        'Medium': 1.0,
                        'High': 10.0}

    def reset(self):
        self.old_total = 0

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool):
        root_sessions = 0
        system_sessions = 0
        for host, info in current_state.items():
            if host == 'success':
                continue

            if 'Sessions' in info:
                for session in info['Sessions']:
                    if session['Agent'] == self.agent_name:
                        # count the number of root sessions
                        if session['Username'] == 'root' and info['System info']['OSType'] == OperatingSystemType.LINUX:
                            root_sessions += self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
                            break
                        # count the number of SYSTEM sessions
                        if session['Username'] == 'SYSTEM' and info['System info']['OSType'] == OperatingSystemType.WINDOWS:
                            system_sessions += self.mapping[self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
                            break

        # find the difference from the old privileged sessions
        total = root_sessions + system_sessions
        reward = total #- self.old_total
        self.old_total = total
        return round(reward, REWARD_MAX_DECIMAL_PLACES)


class DistruptRewardCalculator(RewardCalculator):
    # calculates the reward for disrupting the network
    def __init__(self, agent_name: str, scenario: Scenario):
        super(DistruptRewardCalculator, self).__init__(agent_name)
        self.scenario = scenario
        self.ots = None
        self.mapping = {'None': 0.0,
                        'Low': 0.1,
                        'Medium': 1.0,
                        'High': 10.0}

    def reset(self):
        self.ots = None

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool):
        # currently a single 1 reward is recieved if the Impact action is successful
        # TODO: Add in test to see what required services are up
        agent_action = action[self.agent_name]
        disrupted = []
        if self.ots is None:
            self.ots = []
            for host_info in current_state.values():
                if type(host_info) is not dict:
                    continue
                if 'Processes' in host_info:
                    for proc in host_info['Processes']:
                        if proc['Process Name'] == 'OTService':
                            self.ots.append(host_info['System info']['Hostname'])
        for host_info in current_state.values():
            working = False
            if type(host_info) is not dict:
                continue
            if host_info['System info']['Hostname'] in self.ots:
                if 'Processes' in host_info:
                    for proc in host_info['Processes']:
                        if proc['Process Name'] == 'OTService':
                            working = True
                    if not working:
                        disrupted.append(host_info['System info']['Hostname'])
        # if type(agent_action) is Impact and agent_observations[self.agent_name].data['success'] == True:
        #     if agent_action.hostname not in disrupted:
        #         disrupted.append(agent_action.hostname)
        reward = sum([self.mapping[self.scenario.get_host(i).get('AvailabilityValue', 'Low')] for i in disrupted])
        return round(reward, REWARD_MAX_DECIMAL_PLACES)


class HybridImpactPwnRewardCalculator(RewardCalculator):
    # Hybrid of availability and confidentiality reward calculator
    def __init__(self, agent_name: str, scenario: Scenario):
        super(HybridImpactPwnRewardCalculator, self).__init__(agent_name)
        self.pwn_calculator = PwnRewardCalculator(agent_name, scenario)
        self.disrupt_calculator = DistruptRewardCalculator(agent_name, scenario)

    def reset(self):
        self.pwn_calculator.reset()
        self.disrupt_calculator.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        reward = self.pwn_calculator.calculate_reward(current_state, action, agent_observations, done) \
                 + self.disrupt_calculator.calculate_reward(current_state, action, agent_observations, done)

        return round(reward, REWARD_MAX_DECIMAL_PLACES)
