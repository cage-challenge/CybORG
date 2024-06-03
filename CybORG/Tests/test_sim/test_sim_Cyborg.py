# CLASSIFICATION:       UNCLASSIFIED
#
#         (c) Copyright Commonwealth of Australia 2019
#
# This work is copyright. Apart from any use permitted under the
# Copyright Act 1968, no part may be reproduced or modified by any
# process without prior written permission from the Commonwealth.
#
#  ***  FILE HEADERS AND COPYRIGHT STATEMENTS CANNOT BE REMOVED ***
#
# Direct inquiries to:
# Cyber & Electronic Warfare Division / Defence Science & Technology
#    Team Project Lead: Martin Lucas
#    e-mail Address:    Martin.Lucas@dst.defence.gov.au
##################################################################

from CybORG.Agents import TestAgent
from CybORG.Agents.Wrappers import FixedFlatWrapper
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper
from CybORG.Agents.Wrappers.OpenAIGymWrapper import OpenAIGymWrapper
from CybORG.Agents.training_example import run_training_example
from CybORG.Simulator.SimulationController import SimulationController
from CybORG.Tests.utils import compare_fundamental_observations
import pytest


def test_cyborg_params(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    assert cyborg.scenario_file is not None
    assert type(cyborg.scenario_file) is str
    assert cyborg.environment_controller is not None
    assert type(cyborg.environment_controller) is SimulationController

#
# @pytest.mark.parametrize(['info', 'expected_result'], [
#     ({'Attacker': {'System info': 'All'}},
#      {'Attacker': {
#          'System info': {'Architecture': Architecture.x64,
#                          'Hostname': 'Attacker',
#                          'OSDistribution': OperatingSystemDistribution.KALI,
#                          'OSType': OperatingSystemType.LINUX,
#                          'OSVersion': OperatingSystemVersion.K2019_4}
#      },
#          'success': TrinaryEnum.UNKNOWN
#      }),
#     ({'Attacker': {'User info': 'All'}},
#      {'Attacker': {
#          'User Info': [{'Groups': [{'GID': 0}], 'Username': 'root'},
#                        {'Groups': [{'GID': 1}], 'Username': 'daemon'},
#                        {'Groups': [{'GID': 2}], 'Username': 'bin'},
#                        {'Groups': [{'GID': 3}], 'Username': 'sys'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'sync'},
#                        {'Groups': [{'GID': 60}], 'Username': 'games'},
#                        {'Groups': [{'GID': 12}], 'Username': 'man'},
#                        {'Groups': [{'GID': 7}], 'Username': 'lp'},
#                        {'Groups': [{'GID': 8}], 'Username': 'mail'},
#                        {'Groups': [{'GID': 9}], 'Username': 'news'},
#                        {'Groups': [{'GID': 10}], 'Username': 'uucp'},
#                        {'Groups': [{'GID': 13}], 'Username': 'proxy'},
#                        {'Groups': [{'GID': 33}], 'Username': 'www-data'},
#                        {'Groups': [{'GID': 34}], 'Username': 'backup'},
#                        {'Groups': [{'GID': 38}], 'Username': 'list'},
#                        {'Groups': [{'GID': 39}], 'Username': 'irc'},
#                        {'Groups': [{'GID': 41}], 'Username': 'gnats'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'nobody'},
#                        {'Groups': [{'GID': 65534}], 'Username': '_apt'},
#                        {'Groups': [{'GID': 102}],
#                         'Username': 'systemd-timesync'},
#                        {'Groups': [{'GID': 103}],
#                         'Username': 'systemd-network'},
#                        {'Groups': [{'GID': 104}],
#                         'Username': 'systemd-resolve'},
#                        {'Groups': [{'GID': 110}], 'Username': 'mysql'},
#                        {'Groups': [{'GID': 111}], 'Username': 'ntp'},
#                        {'Groups': [{'GID': 112}],
#                         'Username': 'messagebus'},
#                        {'Groups': [{'GID': 113}], 'Username': 'arpwatch'},
#                        {'Groups': [{'GID': 114}],
#                         'Username': 'Debian-exim'},
#                        {'Groups': [{'GID': 115}], 'Username': 'uuidd'},
#                        {'Groups': [{'GID': 116}], 'Username': 'redsocks'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'rwhod'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'iodine'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'miredo'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'dnsmasq'},
#                        {'Groups': [{'GID': 46}], 'Username': 'usbmux'},
#                        {'Groups': [{'GID': 122}], 'Username': 'rtkit'},
#                        {'Groups': [{'GID': 126}], 'Username': 'stunnel4'},
#                        {'Groups': [{'GID': 65534}], 'Username': 'sshd'},
#                        {'Groups': [{'GID': 127}],
#                         'Username': 'Debian-snmp'},
#                        {'Groups': [{'GID': 128}], 'Username': 'sslh'},
#                        {'Groups': [{'GID': 132}], 'Username': 'avahi'},
#                        {'Groups': [{'GID': 134}], 'Username': 'inetsim'},
#                        {'Groups': [{'GID': 135}], 'Username': 'geoclue'},
#                        {'Groups': [{'GID': 136}], 'Username': 'lightdm'},
#                        {'Groups': [{'GID': 137}],
#                         'Username': 'king-phisher'},
#                        {'Groups': [{'GID': 138}], 'Username': 'dradis'},
#                        {'Groups': [{'GID': 139}], 'Username': 'beef-xss'},
#                        {'Groups': [{'GID': 999}],
#                         'Username': 'systemd-coredump'},
#                        {'Groups': [{'GID': 140}], 'Username': 'nvpd'},
#                        {'Groups': [{'GID': 129}, {'GID': 29}],
#                         'Username': 'pulse'},
#                        {'Groups': [{'GID': 1000},
#                                    {'GID': 4},
#                                    {'GID': 20},
#                                    {'GID': 24},
#                                    {'GID': 25},
#                                    {'GID': 27},
#                                    {'GID': 29},
#                                    {'GID': 30},
#                                    {'GID': 44},
#                                    {'GID': 46},
#                                    {'GID': 109}],
#                         'Username': 'ec2-user'},
#                        {'Groups': [{'GID': 120}, {'GID': 119}],
#                         'Username': 'postgres'}]
#      },
#          'success': TrinaryEnum.UNKNOWN
#      }),
#     ({'Attacker': {'Sessions': 'All'}},
#      {'Attacker': {
#          'Sessions': [{'Username': 'root',
#                        'ID': 0,
#                        'Timeout': 0,
#                        'PID': 12345,
#                        'Type': SessionType.MSF_SERVER,
#                        'Agent': 'Red'}],
#          'Processes': [{'PID': 12345,
#                         'Username': 'root'}]
#      },
#          'success': TrinaryEnum.UNKNOWN
#      }),
#     ({'Attacker': {'Interfaces': 'All'}},
#      {'Attacker': {
#          'Interface': [{'IP Address': IPv4Address('10.0.0.1'),
#                         'Subnet': IPv4Network('10.0.0.0/28'),
#                         'Interface Name': 'eth0'},
#                        {'IP Address': IPv4Address('127.0.0.1'),
#                         'Subnet': IPv4Network('127.0.0.0/8'),
#                         'Interface Name': 'lo'}]
#      },
#          'success': TrinaryEnum.UNKNOWN
#      }),
#     ({'Attacker': {'System info': 'All'},
#       'Gateway': {'System info': 'All'},
#       'Internal': {'System info': 'All'}},
#      {'Attacker': {
#          'System info': {'Architecture': Architecture.x64,
#                          'Hostname': 'Attacker',
#                          'OSDistribution': OperatingSystemDistribution.KALI,
#                          'OSType': OperatingSystemType.LINUX,
#                          'OSVersion': OperatingSystemVersion.K2019_4}
#      },
#          'Gateway': {
#              'System info': {'Architecture': Architecture.x64,
#                              'Hostname': 'Gateway',
#                              'OSDistribution': OperatingSystemDistribution.UBUNTU,
#                              'OSType': OperatingSystemType.LINUX,
#                              'OSVersion': OperatingSystemVersion.U18_04_3}
#          },
#          'Internal': {
#              'System info': {'Architecture': Architecture.x64,
#                              'Hostname': 'Internal',
#                              'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
#                              'OSType': OperatingSystemType.WINDOWS,
#                              'OSVersion': OperatingSystemVersion.W6_1_7601}
#          },
#          'success': TrinaryEnum.UNKNOWN
#      })
# ])
# def test_get_true_obs(create_cyborg_sim, info, expected_result):
#     true_obs = create_cyborg_sim.get_true_state(info)
#     assert true_obs is not None, "True state should exist"
#     assert compare_fundamental_observations(expected_result, true_obs, translation={})


def test_step(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    cyborg.step()


def test_start(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    done = cyborg.start(100)


def test_play(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    for i in range(10):
        done = cyborg.start(10)
        cyborg.reset()


def test_reset_step(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    original_state = cyborg.get_agent_state('True')
    # Make some changes to the state
    cyborg.step()
    # reset
    cyborg.reset()
    new_state = cyborg.get_agent_state('True')
    # Replace PIDs in original_state with those in new_state
    for hostname, hostinfo in original_state.items():
        if hostname != 'success':
            if 'Processes' in hostinfo:
                for p in range(len(hostinfo['Processes'])):
                    hostinfo['Processes'][p]['PID'] = new_state[hostname]['Processes'][p]['PID']
            if 'Sessions' in hostinfo:
                for s in range(len(hostinfo['Sessions'])):
                    if 'PID' in hostinfo['Sessions'][s]:
                        hostinfo['Sessions'][s]['PID'] = new_state[hostname]['Sessions'][s]['PID']
            if 'User Info' in hostinfo:
                for u in range(len(hostinfo['User Info'])):
                    if 'Password' in hostinfo['User Info'][u]:
                        hostinfo['User Info'][u]['Password'] = new_state[hostname]['User Info'][u]['Password']
    # check that the new state is the same as the original state
    assert compare_fundamental_observations(original_state, new_state, {})


def test_reset_start(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    original_state = cyborg.get_agent_state('True')
    # Make some changes to the state
    cyborg.start(steps=1000)
    # reset
    cyborg.reset()
    new_state = cyborg.get_agent_state('True')
    # Replace PIDs in original_state with those in new_state
    for hostname, hostinfo in original_state.items():
        if hostname != 'success':
            if 'Processes' in hostinfo:
                for p in range(len(hostinfo['Processes'])):
                    hostinfo['Processes'][p]['PID'] = new_state[hostname]['Processes'][p]['PID']
            if 'Sessions' in hostinfo:
                for s in range(len(hostinfo['Sessions'])):
                    if 'PID' in hostinfo['Sessions'][s]:
                        hostinfo['Sessions'][s]['PID'] = new_state[hostname]['Sessions'][s]['PID']
            if 'User Info' in hostinfo:
                for u in range(len(hostinfo['User Info'])):
                    if 'Password' in hostinfo['User Info'][u]:
                        hostinfo['User Info'][u]['Password'] = new_state[hostname]['User Info'][u]['Password']
    # check that the new state is the same as the original state
    assert compare_fundamental_observations(original_state, new_state, {})


# def test_custom_agent_loading():
#     path = str(inspect.getfile(CybORG))
#     path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
#     cyborg = CybORG(path, 'sim', agents={'Red': {"agent_type": 'SleepAgent'}})
#     cyborg.start(100)

def test_agent_train(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    agent_name = 'Red'
    cyborg = OpenAIGymWrapper(agent_name=agent_name, env=IntListToActionWrapper(FixedFlatWrapper(cyborg)))


    observation = cyborg.reset(agent=agent_name)
    action_space = cyborg.get_action_space(agent_name)
    action_count = 0
    agent = TestAgent()
    for i in range(100):
        # print(f"\rTraining Game: {i}", end='', flush=True)
        reward = 0
        for j in range(20):
            action = agent.get_action(observation, action_space)
            next_observation, r, terminated, truncated, info = cyborg.step(action)
            done = terminated or truncated
            action_space = info['action_space']
            reward += r

            agent.train(observation)
            observation = next_observation
            if done or j == 20 - 1:
                # print(f"Training reward: {reward}")
                break
        observation = cyborg.reset(agent=agent_name)
        agent.end_episode()

@pytest.mark.parametrize('scenario', ['Scenario1', 'Scenario1b'])
def test_training_example(scenario):
    run_training_example(scenario)
