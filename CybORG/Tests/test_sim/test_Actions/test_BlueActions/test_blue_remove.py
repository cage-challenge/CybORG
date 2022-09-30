# These tests check that the Blue Remove action is working vs Abstract Red Actions.    

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

import pytest

from CybORG import CybORG
import inspect

from CybORG.Shared.Actions import Remove, DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, \
    PrivilegeEscalate, Monitor
from CybORG.Shared.Enums import SessionType, TrinaryEnum
from CybORG.Tests.EphemeralPort import PID
from CybORG.Tests.test_sim.test_Acceptance.test_reward_function import security_values

@pytest.mark.parametrize("seed", [1, 22447, 3242, 4])
def test_blue_remove_killchain_sim_expected_output(seed, security_values):
    # Setup Cyborg
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')
    cyborg.set_seed(seed)

    red_agent = 'Red'
    blue_agent = 'Blue'
    initial_result_red = cyborg.get_observation(red_agent)
    initial_result_blue = cyborg.get_observation(blue_agent)
    blue_session = initial_result_blue['Defender']['Sessions'][0]['ID']

    # Run blue remove with no red activity.
    def blue_remove(host, expected_result, reward = 0.0):
        blue_action = Remove(session=blue_session, agent=blue_agent, hostname=host)
        results = cyborg.step(blue_agent, blue_action)
        assert not results.done
        # assert results.reward == round(reward, 1)
        assert results.observation['success'] == expected_result['success']

    action_space = cyborg.get_action_space('Blue')
    for host in action_space['hostname']:
        expected_result = {"success": True}
        blue_remove(host, expected_result)

    # Begin red killchain

    # Discover Remote Systems
    action_space = cyborg.get_action_space('Red')
    initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]
    for subnet in action_space["subnet"]:
        action = DiscoverRemoteSystems(subnet=subnet, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')

    # Discover Network Services
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
        result = cyborg.step(action=action, agent='Red')

    # Test Exploit
    reward = 0
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if hostname == 'User0' or hostname == 'User1' or hostname == 'User2':
            continue
        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        result = cyborg.step(action=action, agent='Red')

        action = Monitor(agent='Blue', session=blue_session)
        result = cyborg.step(action=action, agent='Blue')

        expected_result = {"success": True}
        blue_remove(hostname, expected_result)

        # Test Remove Stops Red Privilege Escalate
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        result = cyborg.step(action=action, agent='Red')
        if hostname == 'User4' and seed == 22447:
            expected_result = {'Enterprise0': {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise0']}]},
                               'User4': {'Interface': [{'IP Address': address,
                                                        'Interface Name': 'eth0',
                                                        'Subnet': cyborg.environment_controller.subnet_cidr_map['User']}],
                                         'Sessions': [{'Agent': 'Red',
                                                       'ID': 2,
                                                       'Type': SessionType.RED_REVERSE_SHELL,
                                                       'Username': 'root'}]},
                               'success': TrinaryEnum.TRUE}
            reward += security_values[hostname][1]
        else:
            expected_result = {"success": False}
        if hostname not in ('User3', 'User4'):
            assert result.observation == expected_result, f'{hostname} remove failed'

    # Test Escalate
    addresses = [i for i in action_space["ip_address"]]

    for address in addresses:
        if action_space["ip_address"][address]:
            hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
            action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
            result = cyborg.step(action=action, agent='Red')
            # Need to Exploit Again to do Privilege Escalation
            action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
            result = cyborg.step(action=action, agent='Red')
            reward += security_values[hostname][0]
            action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
            result = cyborg.step(action=action, agent='Red')
            reward += security_values[hostname][1] if hostname != 'User4' or seed != 22447 else 0.0

            expected_result = {"success": True}
            blue_remove(hostname, expected_result, reward)

            # Test Remove Fails to Remove Privilege Escalation
            action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
            result = cyborg.step(action=action, agent='Red')
            if hostname != 'User2':
                assert result.observation["success"] == True, f'{hostname} remove succeeded'
