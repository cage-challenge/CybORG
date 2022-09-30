from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
import random
import math

from ipaddress import IPv4Network, IPv4Address

from CybORG.Shared.Actions import NmapScan, SambaUsermapScript, UpgradeToMeterpreter, MSFAutoroute, PingSweep, MSFEternalBlue, GetShell, FindFlag, TomcatCredentialScanner, TomcatExploit, SSHLoginExploit


class KillchainAgent(BaseAgent):

    def __init__(self, action_size=None, state_size=None):

        self.colour = 'Red'
        self.killchains = {
            'smb': [NmapScan, SambaUsermapScript, UpgradeToMeterpreter, MSFAutoroute, PingSweep,
                    MSFEternalBlue, GetShell, FindFlag],
            'tomcat': [NmapScan, TomcatCredentialScanner, TomcatExploit, MSFAutoroute, PingSweep,
                       MSFEternalBlue, GetShell, FindFlag],
            'brute_force': [NmapScan, SSHLoginExploit, UpgradeToMeterpreter, MSFAutoroute, PingSweep,
                            MSFEternalBlue, GetShell, FindFlag],
        }

        self.action_parameters = {
            # 'Sleep':{},
            # 'IFConfig': {'agent': 'Red', 'session': 2},  # For Linux Box
            # 'IPConfig': {'agent': 'Red', 'session': 3},  # For Windows Box
            'FindFlag': {'agent': 'Red', 'session': 5},  # For Windows Box
            # 'SSHAccess':{'agent':'Red', 'session':3},  # From Linux to Windows
            'PingSweep': {'agent': 'Red', 'session': 2, 'subnet': IPv4Network('10.0.1.0/24')},  # From Linux to Windows
            'NmapScan': {'agent': 'Red', 'session': 1, 'subnet': IPv4Network('10.0.0.0/24')},  # From Kali to Linux
            # 'DeleteFileLinux':{'agent':'Red',# 'session':2},
            # 'DeleteFileWindows':{'agent':'Red', 'session':3},
            # 'KillProcessLinux':{'agent':'Red', 'session':2},
            # 'KillProcessWindows':{'agent':'Red', 'session':1},
            # 'AddUserWindows':{'agent':'Red', 'session':1},
            # 'AddUserLinux':{'agent':'Red', 'session':1},
            # 'DisableUserWindows':{'agent':'Red', 'session':1},
            # 'DisableUserLinux':{'agent':'Red', 'session':1},
            # 'RemoveUserFromGroupWindows':{'agent':'Red', 'session':1},
            # 'RemoveUserFromGroupLinux':{'agent':'Red', 'session':1},
            # 'DirtyCowPrivilegeEscalation':{'agent':'Red', 'session'},
            # 'LinuxKernelPrivilegeEscalation':{'agent':'Red', 'session':1},
            # 'SMBAnonymousConnection':{'agent':'Red', 'session':1},
            # 'ShellPS':{'agent':'Red', 'session':1},
            # 'SystemInfo':{'agent':'Red', 'session':1},
            # 'Uname':{'agent':'Red', 'session':1},
            # 'NetcatConnect':{'agent':'Red', 'session':1},
            # 'SSHHydraBruteForce':{'agent':'Red', 'session':1},
            # 'ReadShadowFile':{'agent':'Red', 'session':1},
            # 'ReadPasswdFile':{'agent':'Red', 'session':1},
            # 'StopService':{'agent':'Red', 'session':1},
            # 'StartService':{'agent':'Red', 'session':1},
            'EternalBlue': {'agent': 'Red', 'session': 0, 'ip_address':IPv4Address('10.0.1.2')},
            # 'GetPid':{'agent':'Red', 'session':1},
            'GetShell':{'agent':'Red', 'session':0, 'target_session':4},
            # 'GetUid':{'agent':'Red', 'session':1},
            # 'LocalTime':{'agent':'Red', 'session':1},
            'MSFAutoroute': {'agent': 'Red', 'session': 0, 'target_session': 3},
            # 'MeterpreterPS':{'agent':'Red', 'session':1},
            # 'MeterpreterReboot':{'agent':'Red', 'session':1},
            'SSHLoginExploit':{'agent':'Red', 'session':0, 'ip_address': IPv4Address('10.0.0.2'), 'port':22},
            'SambaUsermapScript': {'agent': 'Red', 'session': 0, 'ip_address': IPv4Address('10.0.0.2')},
            # 'Schtasks':{'agent':'Red', 'session':1},
            # 'SysInfo':{'agent':'Red', 'session':1},
            'TomcatCredentialScanner':{'agent':'Red', 'session':0, 'ip_address': IPv4Address('10.0.0.2'), 'port':8180},
            'TomcatExploit':{'agent':'Red', 'session':0, 'ip_address': IPv4Address('10.0.0.2'), 'port':8180,
                             'username':'tomcat', 'password':'tomcat'},
            'UpgradeToMeterpreter': {'agent': 'Red', 'session': 0, 'target_session': 2}
        }

        self.kchoice = random.choice(list(self.killchains.keys()))
        self.killchain = self.killchains[self.kchoice]
        if self.kchoice == 'tomcat':
            self.action_parameters['MSFAutoroute']['target_session'] -=1
            self.action_parameters['GetShell']['session'] -=1
            self.action_parameters['FindFlag']['session'] -= 1
        self.count = 0

    def train(self, results):
        pass

    def get_action(self, observation, action_space):
        position = self.count % len(self.killchain)
        action_class = self.killchain[position]
        action_params = self.action_parameters[action_class.__name__]
        self.count += 1
        return action_class(**action_params)

    def end_episode(self):
        pass

    def set_initial_values(self, action_space, observation):
        pass

