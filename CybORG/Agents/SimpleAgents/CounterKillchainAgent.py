from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
import random
import math

from ipaddress import IPv4Address

from CybORG.Shared.Actions import VelociraptorPoll, SSHAccess, VelociraptorPoll, KillProcessLinux, VelociraptorPoll, KillProcessLinux


class CounterKillchainAgent(BaseAgent):

    def __init__(self, action_size=None, state_size=None):
        self.colour = 'Blue'
        self.killchains = {
            'kill_process': [VelociraptorPoll, SSHAccess, VelociraptorPoll, KillProcessLinux,
                             VelociraptorPoll, KillProcessLinux]
        }

        self.action_parameters = {
            'Sleep': {},
            #             'IFConfig':{'agent':'Blue','session':0},
            #             'IPConfig':{'agent':'Blue','session':0},
            #             'FindFlag':{'agent':'Blue','session':0},
            'SSHAccess': {'agent': 'Blue', 'session': 1, 'username': 'blue', 'password': 'blue_knight',
                          'ip_address': IPv4Address('10.0.2.1'), 'port': 22},
            #             'PingSweep':{'agent':'Blue','session':0},
            #             'NmapScan':{'agent':'Blue','session':0},
            #             'DeleteFileLinux':{'agent':'Blue','session':0},
            #             'DeleteFileWindows':{'agent':'Blue','session':0},
            'KillProcessLinux': {'agent': 'Blue', 'session': 4, 'process': 0},
            #             'KillProcessWindows':{'agent':'Blue','session':0},
            #             'AddUserWindows':{'agent':'Blue','session':0},
            #             'AddUserLinux':{'agent':'Blue','session':0},
            #             'DisableUserWindows':{'agent':'Blue','session':0},
            #             'DisableUserLinux':{'agent':'Blue','session':0},
            #             'RemoveUserFromGroupWindows':{'agent':'Blue','session':0},
            #             'RemoveUserFromGroupLinux':{'agent':'Blue','session':0},
            #             'SMBAnonymousConnection':{'agent':'Blue','session':0},
            #             'ShellPS':{'agent':'Blue','session':0},
            #             'SystemInfo':{'agent':'Blue','session':0},
            #             'Uname':{'agent':'Blue','session':0},
            #             'NetcatConnect':{'agent':'Blue','session':0},
            #             'SSHHydraBruteForce':{'agent':'Blue','session':0},
            #             'ReadShadowFile':{'agent':'Blue','session':0},
            #             'ReadPasswdFile':{'agent':'Blue','session':0},
            #             'StopService':{'agent':'Blue','session':0},
            #             'StartService':{'agent':'Blue','session':0},
            #             'GetFileInfo':{'agent':'Blue','session':0},
            #             'GetLocalGroups':{'agent':'Blue','session':0},
            #             'GetOSInfo':{'agent':'Blue','session':0},
            #             'GetProcessInfo':{'agent':'Blue','session':0},
            #             'GetProcessList':{'agent':'Blue','session':0},
            #             'GetUsers':{'agent':'Blue','session':0},
            'VelociraptorPoll': {'agent': 'Blue', 'session': 0}
        }

        self.kchoice = random.choice(list(self.killchains.keys()))
        self.killchain = self.killchains[self.kchoice]
        self.count = 0
        self.memory = []

    def train(self, results):
        pass

    def set_initial_values(self, action_space, observation):
        pass

    def get_action(self, observation, action_space):
        pid = self._process_observation(observation)
        if pid is not None:
            self.action_parameters['KillProcessLinux']['process'] = pid
        position = self.count % len(self.killchain)
        action_class = self.killchain[position]
        action_params = self.action_parameters[action_class.__name__]
        self.count += 1
        return action_class(**action_params)

    def _process_observation(self, observation):
        if self.count == 1:
            self.memory = observation['PublicFacing']['Processes']
        else:
            try:
                obs = observation['PublicFacing']['Processes']
            except:
                return None
            for process in obs:
                if (process not in self.memory) \
                        and ('Connections' in process.keys()) \
                        and (process['Username'] != 'blue'):
                    return process['PID']

    def end_episode(self):
        pass
