# These tests check that the Blue Restore action is working vs Abstract Red Actions.    
    
# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address    
    
from CybORG import CybORG    
import inspect

from CybORG.Shared.Actions import Restore, DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, \
    PrivilegeEscalate
from CybORG.Shared.Enums import SessionType, TrinaryEnum
from CybORG.Tests.EphemeralPort import PID
from CybORG.Tests.test_sim.test_Acceptance.test_reward_function import security_values, availability_values


def test_blue_restore_killchain_sim_expected_output(security_values,availability_values):
    # Setup Cyborg
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    red_agent = 'Red'
    blue_agent = 'Blue'
    initial_result_red = cyborg.get_observation(red_agent)
    initial_result_blue = cyborg.get_observation(blue_agent)

    # Run blue restore with no red activity.
    def blue_restore(host, expected_result, reward=-1.0):
        blue_session = initial_result_blue['Defender']['Sessions'][0]['ID']
        blue_action = Restore(session=blue_session, agent=blue_agent, hostname=host)
        results = cyborg.step(blue_agent, blue_action)
        assert not results.done
        assert results.reward == reward, f'Incorrect reward for restore on {hostname}'
        assert results.observation == expected_result

    action_space = cyborg.get_action_space('Blue')
    for host in action_space["hostname"]:
        expected_result = {"success": True}
        blue_restore(host,expected_result)

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
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        result = cyborg.step(action=action, agent='Red')

        expected_result = {"success": True}
        # only user1 and user2 have elevated shells that restore can remove
        blue_restore(hostname, expected_result, -1.0)

        # Test Restore Removes Red
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        result = cyborg.step(action=action, agent='Red')
        if hostname == 'User0':
            expected_result = {hostname: {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map[hostname],
                                          'Interface Name': 'eth0',
                                          'Subnet': IPv4Network(
                                              f'{cyborg.environment_controller.hostname_ip_map[hostname]}/28', False)}],
                           'Processes': [{'PID': PID(), 'Username': 'SYSTEM'}],
                           'Sessions': [{'Agent': 'Red',
                                         'ID': 0,
                                         'Type': SessionType.RED_ABSTRACT_SESSION,
                                         'Username': 'SYSTEM',
                                         'PID': PID(),
                                         'Timeout': 0}]},
                'success': TrinaryEnum.TRUE}
        else:
            expected_result = {'success': False}
        assert result.observation == expected_result

    # Test Escalate
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if 'User' in hostname or 'Enterprise0' == hostname or 'Enterprise1' == hostname:
            # Need to Exploit again to perform privilege escalate
            action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
            result = cyborg.step(action=action, agent='Red')

            action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
            result = cyborg.step(action=action, agent='Red')

            expected_result = {"success": True}
            # only user hosts besides user0 have elevated shells that restore can remove
            blue_restore(hostname, expected_result, -1.0)

            # Test Restore Removes Red
            action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
            result = cyborg.step(action=action, agent='Red')
            if hostname == 'User0':
                expected_result = {hostname: {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map[hostname],
                                              'Interface Name': 'eth0',
                                              'Subnet': IPv4Network(
                                                  f'{cyborg.environment_controller.hostname_ip_map[hostname]}/28',
                                                  False)}],
                               'Processes': [{'PID': PID(), 'Username': 'SYSTEM'}],
                               'Sessions': [{'Agent': 'Red',
                                             'ID': 0,
                                             'Type': SessionType.RED_ABSTRACT_SESSION,
                                             'Username': 'SYSTEM',
                                             'PID': PID(),
                                             'Timeout': 0}]},
                    'success': TrinaryEnum.TRUE}
            else:
                expected_result = {'success':False}
            assert result.observation == expected_result
