# These tests check that the Blue Monitor action is working vs Abstract Red Actions.    

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently

import inspect

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions import Monitor, DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, \
    PrivilegeEscalate, Impact
from CybORG.Shared.Enums import TrinaryEnum, OperatingSystemDistribution, Architecture, OperatingSystemType, \
    OperatingSystemVersion
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort, PID

import pytest


@pytest.mark.skip('Monitor is no longer a supported action for the Blue agent')
@pytest.mark.parametrize("seed", [1, 22447, 3242, 4])
def test_blue_monitor_on_red_killchain(seed):
    # create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    cyborg.set_seed(seed)

    # Run blue monitor with no red activity.
    blue_session = cyborg.get_observation('Blue')['Defender']['Sessions'][0]['ID']

    def blue_monitor(expected_result, reward=0.0):
        blue_action = Monitor(session=blue_session, agent='Blue')
        results = cyborg.step('Blue', blue_action)
        assert not results.done
        assert results.reward == reward
        assert results.observation == expected_result

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
        blue_monitor(expected_observation)

    # test discover network services
    # act on ip addresses discovered in first subnet
    addresses = [i for i in action_space["ip_address"]]
    attacker_address = cyborg.environment_controller.hostname_ip_map['User0']
    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {hostname: {'Interface': [{'IP Address': address}],
                                               'Processes': [
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 22,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 135,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 3389,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 445,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 139,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': hostname,
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                    'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {hostname: {'Interface': [{'IP Address': address}],
                                               'Processes': [
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 22,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': LinuxEphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 80,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': LinuxEphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': hostname,
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                                    'success': TrinaryEnum.TRUE}
        else:
            raise ValueError
        action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        blue_monitor(expected_observation)

    # test exploit action by acting on all known ip_addresses
    # own all hosts on the client subnet
    for address in addresses:
        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        hostname = {v: i for i, v in cyborg.environment_controller.hostname_ip_map.items()}[address]
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.TRUE}
        elif seed == 1 and address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {hostname: {'Interface': [{'IP Address': address}],
                                               'Processes': [{'Connections': [{'local_address': address,
                                                                               'local_port': 139,
                                                                               'remote_address': attacker_address,
                                                                               'remote_port': Win2008EphemeralPort()}]}
                                                             ],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': hostname,
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                    'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] or address == \
                cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {hostname: {'Interface': [{'IP Address': address}],
                                               'Processes': [{'Connections': [{'local_address': address,
                                                                               'local_port': 139,
                                                                               'remote_address': attacker_address,
                                                                               'remote_port': Win2008EphemeralPort()}]},
                                                             {'Connections': [{'local_address': address,
                                                                               'local_port': Win2008EphemeralPort(),
                                                                               'remote_address': attacker_address,
                                                                               'remote_port': 4444}],
                                                              'PID': PID()}
                                                             ],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': hostname,
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                    'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] or address == \
                cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {hostname: {'Interface': [{'IP Address': address}],
                                               'Processes': [
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': 80,
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': Win2008EphemeralPort()}]},
                                                   {'Connections': [{'local_address': address,
                                                                     'local_port': LinuxEphemeralPort(),
                                                                     'remote_address': attacker_address,
                                                                     'remote_port': 4444}],
                                                    'PID': PID()}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': hostname,
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                                    'success': TrinaryEnum.TRUE}
        else:
            raise NotImplementedError

        blue_monitor(expected_observation)

    # priv esc on all hosts in client subnet
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 2
    for hostname in hostnames:
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        expected_observation = {'success': TrinaryEnum.TRUE}
        blue_monitor(expected_observation)

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
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise0']:
            expected_observation = {'Enterprise0': {'Interface': [{'IP Address': address}],
                                                    'Processes': [
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 22,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise0',
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                                    'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise1']:
            expected_observation = {'Enterprise1': {'Interface': [{'IP Address': address}],
                                                    'Processes': [
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 22,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 135,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 3389,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 445,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 139,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 80,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]},
                                                        {'Connections': [{'local_address': address,
                                                                          'local_port': 443,
                                                                          'remote_address': attacker_address,
                                                                          'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise1',
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                    'success': TrinaryEnum.TRUE}
        else:
            raise ValueError(f'{address} not accounted for')
        action = DiscoverNetworkServices(agent='Red', ip_address=address, session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        blue_monitor(expected_observation)

    # exploit hosts in enterprise subnet
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
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise0']:
            expected_observation = {'Enterprise0': {'Interface': [{'IP Address': address}],
                                                    'Processes': [{'Connections': [{'local_address': address,
                                                                                    'local_port': 22,
                                                                                    'remote_address': attacker_address,
                                                                                    'remote_port': LinuxEphemeralPort()}]}
                                                                  for i in range(11)],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise0',
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                                    'success': TrinaryEnum.TRUE}
            count += 1
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise1']:
            if seed == 3242:
                expected_observation = {'Enterprise1': {'Interface': [{'IP Address': address}],
                                                        'Processes': [
                                                            {'Connections': [{'local_address': address,
                                                                              'local_port': 443,
                                                                              'remote_address': attacker_address,
                                                                              'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise1',
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                        'success': TrinaryEnum.TRUE}
            else:
                expected_observation = {'Enterprise1': {'Interface': [{'IP Address': address}],
                                                        'Processes': [
                                                            {'Connections': [{'local_address': address,
                                                                              'local_port': 443,
                                                                              'remote_address': attacker_address,
                                                                              'remote_port': Win2008EphemeralPort()}]},
                                                            {'Connections': [{'local_address': address,
                                                                              'local_port': LinuxEphemeralPort(),
                                                                              'remote_address': attacker_address,
                                                                              'remote_port': 4444}],
                                                             'PID': PID()}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise1',
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                                        'success': TrinaryEnum.TRUE}
            count += 1
        else:
            raise ValueError
        action = ExploitRemoteService(agent='Red', ip_address=address, session=session)
        cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        blue_monitor(expected_observation)

    # priv esc hosts in enterprise subnet
    enterprise_subnet = cyborg.environment_controller.subnet_cidr_map['Enterprise']
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 6
    for hostname in hostnames:
        action = PrivilegeEscalate(agent='Red', hostname=hostname, session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        expected_observation = {'success': TrinaryEnum.TRUE}
        blue_monitor(expected_observation)

    # scan enterprise subnet
    action_space = cyborg.get_action_space('Red')
    assert enterprise_subnet in action_space['subnet']
    assert action_space['subnet'][enterprise_subnet]
    action = DiscoverRemoteSystems(agent='Red', subnet=enterprise_subnet, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # scan the third enterprise host
    enterprise2_ip = cyborg.environment_controller.hostname_ip_map['Enterprise2']
    assert enterprise2_ip in action_space['ip_address']
    assert action_space['ip_address'][enterprise2_ip]
    action = DiscoverNetworkServices(agent='Red', ip_address=enterprise2_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Enterprise2': {'Interface': [{'IP Address': enterprise2_ip}],
                                            'Processes': [
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 22,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 135,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 3389,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 445,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 139,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 80,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 443,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise2',
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                            'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # exploit the 3rd enterprise host
    action = ExploitRemoteService(agent='Red', ip_address=enterprise2_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Enterprise2': {'Interface': [{'IP Address': enterprise2_ip}],
                                            'Processes': [
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': 443,
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': Win2008EphemeralPort()}]},
                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                  'local_port': LinuxEphemeralPort(),
                                                                  'remote_address': attacker_address,
                                                                  'remote_port': 4444}],
                                                 'PID': PID()}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Enterprise2',
                           'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
                           'OSType': OperatingSystemType.WINDOWS,
                           'OSVersion': OperatingSystemVersion.W6_1_7601}},
                            'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # priv esc on enterprise host
    assert 'Enterprise2' in action_space['hostname']
    assert action_space['hostname']['Enterprise2']
    action = PrivilegeEscalate(agent='Red', hostname='Enterprise2', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # scan the op server
    op_server_ip = cyborg.environment_controller.hostname_ip_map['Op_Server0']
    assert op_server_ip in action_space['ip_address']
    assert action_space['ip_address'][op_server_ip]
    action = DiscoverNetworkServices(agent='Red', ip_address=op_server_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Op_Server0': {'Interface': [{'IP Address': op_server_ip}],
                                           'Processes': [{'Connections': [{'local_address': op_server_ip,
                                                                           'local_port': 22,
                                                                           'remote_address': attacker_address,
                                                                           'remote_port': Win2008EphemeralPort()}]}],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Op_Server0',
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                            'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # exploit the op server
    count = 9
    action = ExploitRemoteService(agent='Red', ip_address=op_server_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Op_Server0': {'Interface': [{'IP Address': op_server_ip}],
                                           'Processes': [{'Connections': [{'local_address': op_server_ip,
                                                                           'local_port': 22,
                                                                           'remote_address': attacker_address,
                                                                           'remote_port': LinuxEphemeralPort()}]}
                                                         for i in range(11)],
           'System info': {'Architecture': Architecture.x64,
                           'Hostname': 'Op_Server0',
                           'OSDistribution': OperatingSystemDistribution.UBUNTU,
                           'OSType': OperatingSystemType.LINUX,
                           'OSVersion': OperatingSystemVersion.U18_04_3}},
                            'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    # priv esc on op server
    action = PrivilegeEscalate(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation)

    action = Impact(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    blue_monitor(expected_observation, reward=-10.0)
