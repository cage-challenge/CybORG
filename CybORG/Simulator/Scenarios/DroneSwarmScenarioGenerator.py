from ipaddress import IPv4Network
from math import log2, ceil

import numpy as np


from CybORG.Agents import DroneRedAgent
from CybORG.Agents.SimpleAgents.DroneTrojanAgent import DroneTrojanAgent
from CybORG.Agents.SimpleAgents.GreenDroneAgent import GreenDroneAgent
from CybORG.Agents.SimpleAgents.RedDroneWorm import RedDroneWormAgent
from CybORG.Shared import Scenario
from CybORG.Simulator.Actions import Sleep
from CybORG.Simulator.Actions.ConcreteActions.ActivateTrojan import ActivateTrojan
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic, AllowTraffic
from CybORG.Simulator.Actions.ConcreteActions.EscalateActions.SeizeControl import SeizeControl
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitDroneVulnerability import ExploitDroneVulnerability
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl
from CybORG.Simulator.Actions.ConcreteActions.FloodBandwidth import FloodBandwidth
from CybORG.Simulator.Actions.ConcreteActions.GetDroneSwarmData import GetDroneSwarmData
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions
from CybORG.Simulator.Actions.GreenActions.SendData import SendData
from CybORG.Shared.CommsRewardCalculator import CommsAvailabilityRewardCalculator, CompleteCompromiseRewardCalculator
from CybORG.Shared.Scenario import ScenarioHost, ScenarioSubnet, ScenarioAgent, ScenarioSession
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator


# from CybORG.Agents.Wrappers import PettingZooParallelWrapper


class DroneSwarmScenarioGenerator(ScenarioGenerator):
    """Creates a drone swarm scenario"""

    def __init__(self, max_length_data_links=30, data_link_bandwidth=100, num_drones=18, starting_num_red=0,
                 starting_positions=None, default_red_agent=None, red_spawn_rate: float = 0.05,
                 red_internal_only: bool = True, agent_to_drone_mapping: dict = None, maximum_steps: int = 500, all_external=False):
        super().__init__()
        self.background = "map_background"
        self.max_length_data_links = max_length_data_links
        self.data_link_bandwidth = data_link_bandwidth
        self.num_drones = num_drones
        self.starting_num_red = starting_num_red
        self.red_spawn_rate = red_spawn_rate
        self.red_internal_only = red_internal_only and not all_external
        self.all_external = all_external
        self.update_each_step = False
        self.maximum_steps = maximum_steps
        if default_red_agent is None:
            self.default_red_agent = RedDroneWormAgent
        else:
            self.default_red_agent = default_red_agent
        if starting_positions is None or len(starting_positions) == num_drones:
            self.starting_positions = starting_positions
        else:
            print(
                f"Starting postions of length {len(starting_positions)} does not match number of drones {num_drones}, so starting positions are randomised")
            self.starting_positions = None
        if agent_to_drone_mapping is None:
            self.agent_to_drone_mapping = {}
        else:
            self.agent_to_drone_mapping = agent_to_drone_mapping

    def determine_done(self, env_controller):
        return len([i for i in env_controller.get_active_agents() if 'blue' in i]) == 0 or env_controller.step_count >= self.maximum_steps

    def create_scenario(self, np_random) -> Scenario:
        scenario = Scenario()

        red_actions = [ExploitDroneVulnerability, SeizeControl, FloodBandwidth, BlockTraffic, AllowTraffic, Sleep]
        blue_actions = [RetakeControl, RemoveOtherSessions, BlockTraffic, AllowTraffic, Sleep]
        green_actions = [SendData, Sleep]

        blue_event_artifacts = []
        if self.starting_positions is None:
            starting_positions = np_random.choice([np.array([i, j]) for i in range(100) for j in range(100)], self.num_drones, replace=False)
        else:
            starting_positions = self.starting_positions

        subnet_prefix = 32 - max(ceil(log2(self.num_drones + 5)), 4)
        subnet_cidr = np_random.choice(list(IPv4Network("10.0.0.0/16").subnets(new_prefix=subnet_prefix)))
        ip_address_selection = np_random.choice(list(subnet_cidr.hosts()), self.num_drones, replace=False)

        # set up all hosts and add an active blue and green agent, and a potential red agent to that host
        if self.starting_num_red > 0:
            red_drones = np_random.choice(range(self.num_drones), self.starting_num_red, replace=False)
        else:
            red_drones = [k for k, i in self.agent_to_drone_mapping.items() if 'red' in i.lower()]
        for i in range(self.num_drones):
            scenario.hosts[f'drone_{i}'] = ScenarioHost(hostname=f'drone_{i}',
                                                        host_type='drone',
                                                        processes=[  # drone_comms on port 8888
                                                            {'Connections': [{
                                                                'local_address': '0.0.0.0',
                                                                'local_port': 8888,
                                                                'Transport Protocol': 'TCP'}],
                                                                'PID': 1056,
                                                                'PPID': 1,
                                                                'Path': '/ usr / sbin',
                                                                'Process Name': 'drone_comms',
                                                                'Username': 'drone_user'},  # 8888
                                                            # ssh on port 22
                                                            {'Connections': [{
                                                                'local_address': '0.0.0.0',
                                                                'local_port': 22,
                                                                'Transport Protocol': 'TCP'}],
                                                                'PID': 1091,
                                                                'PPID': 1,
                                                                'Path': '/ usr / sbin',
                                                                'Process Name': 'sshd',
                                                                'Username': 'root'}
                                                        ],
                                                        system_info={'OSType': 'linux',
                                                                     "OSDistribution": 'DroneLinux',
                                                                     # TODO replace with correct distro
                                                                     "OSVersion": "unknown",
                                                                     "Architecture": "unknown"
                                                                     },
                                                        interface_info=[{"name": 'wlan0',
                                                                         "ip_address": ip_address_selection[i],
                                                                         "subnet": subnet_cidr,
                                                                         'interface_type': 'wireless',
                                                                         'max_range': self.max_length_data_links,
                                                                         'swarm': True}],
                                                        user_info=[{'Groups': [{'GID': 0,
                                                                                'Group Name': 'root'}],
                                                                    'UID': 0,
                                                                    'Username': 'root'},
                                                                   {'Groups': [{'GID': 0,
                                                                                'Group Name': 'drone_user'}],
                                                                    'UID': 1000,
                                                                    'Username': 'drone_user'}],
                                                        services={},
                                                        starting_position=starting_positions[i])
            scenario.agents[f'red_agent_{i}'] = ScenarioAgent(agent_name=f'red_agent_{i}',
                                                              team='Red',
                                                              starting_sessions=[ScenarioSession(username='root',
                                                                                                 session_type='red_drone_session',
                                                                                                 hostname=f'drone_{i}',
                                                                                                 name=f'red_session_{i}')
                                                                                 for _ in [1]
                                                                                 if i in red_drones],
                                                              actions=red_actions,
                                                              osint={'Hosts': {
                                                                  f'drone_{j}':
                                                                      ({'Interfaces': 'All',
                                                                        'System info': 'All',
                                                                        'User info': 'All'}
                                                                       if i == j
                                                                       else {'Interfaces': 'All', 'System info': 'All'})
                                                                  for j in
                                                                  range(self.num_drones)}},
                                                              allowed_subnets=['Adhoc'],
                                                              active=i in red_drones,
                                                              default_actions=(GetDroneSwarmData, {'session': 0,
                                                                                                      'agent': f'red_agent_{i}'}),
                                                              agent_type=self.default_red_agent(name=f'red_agent_{i}',
                                                                                                np_random=np_random),
                                                              internal_only=self.red_internal_only)
            scenario.agents[f'blue_agent_{i}'] = ScenarioAgent(agent_name=f'blue_agent_{i}',
                                                               team='Blue',
                                                               starting_sessions=[ScenarioSession(username='root',
                                                                                                  session_type='blue_drone_session',
                                                                                                  hostname=f'drone_{i}',
                                                                                                  event_artifacts=blue_event_artifacts,
                                                                                                  name=f'blue_session_{i}')
                                                                                  for _ in [1]
                                                                                  if i not in red_drones],
                                                               actions=blue_actions,
                                                               osint={'Hosts': {
                                                                   f'drone_{j}':
                                                                       ({'Interfaces': 'All',
                                                                         'System info': 'All',
                                                                         'User info': 'All'}
                                                                        if i == j
                                                                        else {'Interfaces': 'All',
                                                                              'System info': 'All'}) for j in
                                                                   range(self.num_drones)}},
                                                               allowed_subnets=['Adhoc'],
                                                               active=i not in red_drones,
                                                               default_actions=(GetDroneSwarmData, {'session': 0,
                                                                                                    'agent': f'blue_agent_{i}'}))
            scenario.agents[f'green_agent_{i}'] = ScenarioAgent(agent_name=f'green_agent_{i}',
                                                                team='Green',
                                                                starting_sessions=[ScenarioSession(username='hardware',
                                                                                                   session_type='green_session',
                                                                                                   hostname=f'drone_{i}',
                                                                                                   name=f'green_session_{i}')],
                                                                actions=green_actions,
                                                                osint={'Hosts': {
                                                                    f'drone_{j}':
                                                                        ({'Interfaces': 'All',
                                                                          'System info': 'All',
                                                                          'User info': 'All'}
                                                                         if i == j
                                                                         else {'Interfaces': 'All'}) for j in
                                                                    range(self.num_drones)}},
                                                                allowed_subnets=['Adhoc'],
                                                                internal_only=not self.all_external,
                                                                agent_type=GreenDroneAgent(name=f'green_agent_{i}', own_ip=ip_address_selection[i]))

        scenario.agents[f'Red_Trojan'] = ScenarioAgent(agent_name=f'Red_Trojan',
                                                       team='Red',
                                                       starting_sessions=[],
                                                       actions=[ActivateTrojan, Sleep],
                                                       osint={'Hosts': {
                                                           f'drone_{j}':
                                                               {'Interfaces': 'All',
                                                                'System info': 'All',
                                                                'User info': 'All'} for j in
                                                           range(self.num_drones)}},
                                                       allowed_subnets=['Adhoc'],
                                                       active=True,
                                                       agent_type=DroneTrojanAgent(self.num_drones, 'Red_Trojan', np_random, self.red_spawn_rate),
                                                       internal_only=not self.all_external)

        scenario.team_agents = {'Red': [f'red_agent_{i}' for i in range(self.num_drones)]+[f'Red_Trojan'],
                                'Blue': [f'blue_agent_{i}' for i in range(self.num_drones)],
                                'Green': [f'green_agent_{i}' for i in range(self.num_drones)]}

        scenario.team_calc = {'Red': {},
                              'Blue': {'CommunicationAvailability': CommsAvailabilityRewardCalculator('Green'),
                                       'CompleteCompromise': CompleteCompromiseRewardCalculator(self.maximum_steps)},
                              # {PettingZooParallelWrapper.calculate_green_reward()},
                              'Green': {}}

        scenario.subnets['Adhoc'] = ScenarioSubnet(subnet_name='Adhoc', size=self.num_drones, cidr=subnet_cidr,
                                                   ip_addresses=ip_address_selection,
                                                   hosts=list(scenario.hosts.keys()))

        scenario.max_bandwidth = self.data_link_bandwidth
        return scenario
