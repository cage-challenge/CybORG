# These tests check that the Blue Monitor action is working vs Abstract Red Actions.    

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently

import inspect

from CybORG import CybORG
from CybORG.Shared.Actions import DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, \
    PrivilegeEscalate, Impact, Analyse
from CybORG.Shared.Enums import TrinaryEnum, FileType, Path
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort
from CybORG.Tests.test_sim.test_Acceptance.test_reward_function import security_values, availability_values

import pytest
from CybORG.Agents import B_lineAgent


def test_blue_analyse_on_red_killchain(security_values,availability_values):
    # create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    # Run blue monitor with no red activity.
    blue_session = cyborg.get_observation('Blue')['Defender']['Sessions'][0]['ID']
    blue_hosts = cyborg.get_action_space('Blue')['hostname']

    def blue_analyse(expected_result, host, reward=0.0):
        blue_action = Analyse(session=blue_session, agent='Blue', hostname=host)
        results = cyborg.step('Blue', blue_action)
        assert not results.done
        # assert results.reward == round(reward, 1)
        assert results.observation['success'] == expected_result['success'] # TODO: Refactor to check more of obs

    windows_reverse_shell = {'Density': 0.9,
                             'File Name': 'cmd.exe',
                             'Known File': FileType.UNKNOWN,
                             'Known Path': Path.TEMP,
                             'Path': 'C:\\temp\\',
                             'Signed': False}
    linux_reverse_shell = {'Density': 0.9,
                           'File Name': 'cmd.sh',
                           'Known File': FileType.UNKNOWN,
                           'Known Path': Path.TEMP,
                           'Path': '/tmp/',
                           'Signed': False}
    windows_potato_exploit = {'Density': 0.9,
                              'File Name': 'escalate.exe',
                              'Known File': FileType.UNKNOWN,
                              'Known Path': Path.TEMP,
                              'Path': 'C:\\temp\\',
                              'Signed': False}

    linux_kernel_exploit = {'Density': 0.9,
                            'File Name': 'escalate.sh',
                            'Known File': FileType.UNKNOWN,
                            'Known Path': Path.TEMP,
                            'Path': '/tmp/',
                            'Signed': False}

    # test discover remote systems
    # act on all subnets in action space
    action_space = cyborg.get_action_space('Red')
    initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]
    for subnet in action_space["subnet"]:
        # ping sweep leaves no artifacts for scenario1b
        expected_observation = {'success': TrinaryEnum.TRUE}

        action = DiscoverRemoteSystems(subnet=subnet, agent='Red', session=session)
        cyborg.step(action=action, agent='Red')

        # test if output of observation matches expected output
        for host in blue_hosts:
            blue_analyse(expected_observation, host)

    # test discover network services
    # act on ip addresses discovered in first subnet
    addresses = [i for i in action_space["ip_address"]]
    attacker_address = cyborg.environment_controller.hostname_ip_map['User0']
    for address in addresses:
        expected_observation = {'success': TrinaryEnum.TRUE}
        action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        for host in blue_hosts:
            blue_analyse(expected_observation, host)

    # test exploit action by acting on all known ip_addresses
    # own all hosts on the client subnet
    reward = 0
    for address in addresses:
        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] or address == \
                cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {hostname: {'Files': [windows_reverse_shell]},
                                    'success': TrinaryEnum.TRUE}
            reward += security_values[hostname][0]
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] or address == \
                cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {hostname: {'Files': [linux_reverse_shell]},
                                    'success': TrinaryEnum.TRUE}
        else:
            raise NotImplementedError

        blue_analyse(expected_observation, hostname, reward)

    # priv esc on all hosts in client subnet
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 2
    for hostname in hostnames:
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        cyborg.step(action=action, agent='Red')
        if hostnames[hostname]:
            last_action = cyborg.get_last_action('Red')
            assert last_action == action
        # test if output of observation matches expected output
        if 'User' in hostname:
            if '0' in hostname or '1' in hostname or '2' in hostname:
                expected_observation = {hostname: {'Files': [windows_reverse_shell]},
                                        'success': TrinaryEnum.TRUE}
            else:
                expected_observation = {hostname: {'Files': [linux_reverse_shell,
                                                             linux_kernel_exploit]},
                                        'success': TrinaryEnum.TRUE}
                reward += security_values[hostname][1]
        else:
            expected_observation = {'success': TrinaryEnum.TRUE}

        blue_analyse(expected_observation, host=hostname, reward=reward)

    # recon hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        if not action_space["ip_address"][address] \
                or address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            continue
        else:
            expected_observation = {'success': TrinaryEnum.TRUE}
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        blue_analyse(expected_observation, hostname, reward)

    # exploit hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]

    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if not action_space["ip_address"][address] \
                or address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            continue
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise0']:
            expected_observation = {'success': TrinaryEnum.TRUE}
            count += 1
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise1']:
            expected_observation = {hostname: {'Files': [windows_reverse_shell]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
        else:
            raise ValueError

        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        blue_analyse(expected_observation, hostname, reward)

    # priv esc hosts in enterprise subnet
    enterprise_subnet = cyborg.environment_controller.subnet_cidr_map['Enterprise']
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 6
    for hostname in hostnames:
        if 'User' in hostname:
            continue
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        result = cyborg.step(action=action, agent='Red')

        # test if output of observation matches expected output
        if hostname == 'Enterprise0':
            expected_observation = {'Enterprise0': {'Files': [linux_kernel_exploit]},
                                    'success': TrinaryEnum.TRUE}
            reward += -1.0
        elif hostname == 'Enterprise1':
            expected_observation = {'Enterprise1': {'Files': [windows_reverse_shell,
                                                              windows_potato_exploit]},
                                    'success': TrinaryEnum.TRUE}
            reward += -1.0
        else:
            expected_observation = {'success': TrinaryEnum.TRUE}
        blue_analyse(expected_observation, hostname, reward)

    # scan enterprise subnet
    action_space = cyborg.get_action_space('Red')
    assert enterprise_subnet in action_space['subnet']
    assert action_space['subnet'][enterprise_subnet]
    action = DiscoverRemoteSystems(agent='Red', subnet=enterprise_subnet, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Enterprise2', reward)

    # scan the third enterprise host
    enterprise2_ip = cyborg.environment_controller.hostname_ip_map['Enterprise2']
    assert enterprise2_ip in action_space['ip_address']
    assert action_space['ip_address'][enterprise2_ip]
    action = DiscoverNetworkServices(agent='Red', ip_address=enterprise2_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Enterprise2', reward)

    # exploit the 3rd enterprise host
    action = ExploitRemoteService(agent='Red', ip_address=enterprise2_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Enterprise2': {'Files': [windows_reverse_shell]},
                            'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Enterprise2', reward)

    # priv esc on enterprise host
    assert 'Enterprise2' in action_space['hostname']
    assert action_space['hostname']['Enterprise2']
    action = PrivilegeEscalate(agent='Red', hostname='Enterprise2', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Enterprise2': {'Files': [windows_reverse_shell,
                                                      windows_potato_exploit]},
                            'success': TrinaryEnum.TRUE}
    reward += -1.0
    blue_analyse(expected_observation, 'Enterprise2', reward)

    # scan the op server
    op_server_ip = cyborg.environment_controller.hostname_ip_map['Op_Server0']
    assert op_server_ip in action_space['ip_address']
    assert action_space['ip_address'][op_server_ip]
    action = DiscoverNetworkServices(agent='Red', ip_address=op_server_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Op_Server0', reward)

    # exploit the op server
    count = 9
    action = ExploitRemoteService(agent='Red', ip_address=op_server_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Op_Server0', reward)

    # priv esc on op server
    action = PrivilegeEscalate(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Op_Server0': {'Files': [linux_kernel_exploit]},
                            'success': TrinaryEnum.TRUE}
    reward += -1.0
    blue_analyse(expected_observation, 'Op_Server0', reward)

    action = Impact(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Op_Server0': {'Files': [linux_kernel_exploit]},
                            'success': TrinaryEnum.TRUE}
    blue_analyse(expected_observation, 'Op_Server0', reward=reward-10.0)

@pytest.fixture()
def cyborg(request,agents = {'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents=agents)
    cyborg.set_seed(seed)
    return cyborg

def test_analyse_bug_aug19(cyborg):
    cyborg.reset()
    for i in range(10):
        action = Analyse(session=0,agent='Blue',hostname='Enterprise0')
        results = cyborg.step(action=action,agent='Blue')
        obs = results.observation
        for hostid, host in obs.items():
            if hostid == 'success':
                continue
            if hostid != 'Enterprise0':
                assert 'Processes' in host, f'repeats: {i}'
                for process in host['Processes']:
                    assert 'Connections' in process

        


