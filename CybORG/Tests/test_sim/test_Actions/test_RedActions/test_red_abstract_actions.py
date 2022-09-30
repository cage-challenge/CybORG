# these tests check that the abstract actions are working:
# DiscoverRemoteSystems, DiscoverNetworkServices, ExploitService, Escalate, Impact

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

from CybORG import CybORG
import inspect
import pytest

from CybORG.Shared.Actions import PrivilegeEscalate, Impact
from CybORG.Shared.Actions.AbstractActions.DiscoverNetworkServices import DiscoverNetworkServices
from CybORG.Shared.Actions.AbstractActions.DiscoverRemoteSystems import DiscoverRemoteSystems
from CybORG.Shared.Actions.AbstractActions.ExploitRemoteService import ExploitRemoteService
from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import lo_subnet, lo
from CybORG.Shared.Enums import TrinaryEnum, ProcessType, ProcessState, SessionType, OperatingSystemType
from CybORG.Shared.RedRewardCalculator import REWARD_MAX_DECIMAL_PLACES
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, PID, LinuxEphemeralPort

@pytest.mark.skip
def test_red_killchain_scenario1b():
    # create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    # test discover remote systems
    # act on all subnets in action space
    action_space = cyborg.get_action_space('Red')
    initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]

    def red_remote_system_discover(expected_observation, subnet, reward):
        action = DiscoverRemoteSystems(subnet=subnet, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
        assert not result.done
        assert result.observation['success'] == expected_observation['success'], f'failed scan of {subnet}'

    def red_remote_service_discover(expected_observation, ip_address, reward):
        action = DiscoverNetworkServices(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
        assert not result.done
        assert result.observation['success'] == expected_observation['success']

    def red_remote_service_exploit(expected_observation, ip_address, reward):
        action = ExploitRemoteService(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
        assert not result.done
        assert result.observation['success'] == expected_observation['success']

    def red_privilege_escalate(expected_observation, hostname, reward):
        action = PrivilegeEscalate(hostname=hostname, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
        assert not result.done
        assert result.observation['success'] == expected_observation['success']

    for subnet in action_space["subnet"]:
        if not action_space["subnet"][subnet]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1
        else:
            expected_observation = {str(cyborg.environment_controller.hostname_ip_map['User' + str(i)]): {'Interface':
                [{
                    'IP Address':
                        cyborg.environment_controller.hostname_ip_map[
                            'User' + str(
                                i)],
                    'Subnet': subnet}]}
                for i in range(5)}
            reward = 0
            expected_observation.update({'success': True})
        red_remote_system_discover(expected_observation, subnet, reward)

    # test discover network services
    # act on ip addresses discovered in first subnet
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 135}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 3389}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 445}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 139}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = 0
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 80}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = 0
        else:
            raise ValueError
        red_remote_service_discover(expected_observation, address, reward)

    # test exploit action by acting on all known ip_addresses
    count = 1
    initial_ip_address = initial_observation['User0']['Interface'][0]['IP Address']
    # own all hosts on the client subnet
    reward = 0
    for address in addresses:
        # test if output of observation matches expected output
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            temp_reward = reward - 0.1
        elif address == initial_ip_address:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': 4444,
                                                                                   'remote_address': address,
                                                                                   'remote_port': Win2008EphemeralPort()}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION_HANDLER},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': Win2008EphemeralPort(),
                                                                                   'remote_address': address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 139,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.SMB}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': 'User0',
                                                                   'OSType': OperatingSystemType.WINDOWS}
                                                   },
                                    'success': TrinaryEnum.TRUE}
            count += 1
            temp_reward = reward
        elif address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
    
                                                                                   'local_port': Win2008EphemeralPort(),
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 139,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.SMB}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.WINDOWS}
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': 4444,
                                                                                    'remote_address': address,
                                                                                    'remote_port': Win2008EphemeralPort()}],
                                                                   'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
            reward += 0.1
            temp_reward = reward
        elif address == \
                cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': LinuxEphemeralPort(),
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 80,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.WEBSERVER}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.LINUX}
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': 4444,
                                                                                    'remote_address': address,
                                                                                    'remote_port': LinuxEphemeralPort()}],
                                                                   'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                                    'success': TrinaryEnum.TRUE}
            temp_reward = reward
            count += 1
        else:
            raise NotImplementedError

        red_remote_service_exploit(expected_observation, address, temp_reward)

    # priv esc on all hosts in client subnet
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 2
    for hostname in hostnames:
        # test if output of observation matches expected output
        if not action_space["hostname"][hostname]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            temp_reward = reward-0.1
        elif hostname == 'User0':
            expected_observation = {hostname: {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map[hostname],
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
            temp_reward = reward

        elif hostname == 'User1' or hostname == 'User2':
            expected_observation = {'Enterprise1': {
                'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise1']}]},
                hostname: {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map[hostname],
                                          'Interface Name': 'eth0',
                                          'Subnet': IPv4Network(
                                              f'{cyborg.environment_controller.hostname_ip_map[hostname]}/28', False)}],
                           'Processes': [{'PID': PID(), 'Username': 'SYSTEM'}],
                           'Sessions': [{'Agent': 'Red',
                                         'ID': count,
                                         'Type': SessionType.RED_REVERSE_SHELL,
                                         'Username': 'SYSTEM',
                                         'PID': PID(),
                                         'Timeout': 0}]},
                'success': TrinaryEnum.TRUE}
            count += 1
            temp_reward = reward
        elif hostname == 'User3' or hostname == 'User4':
            expected_observation = {'Enterprise0': {
                'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise0']}]},
                hostname: {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map[hostname],
                                          'Interface Name': 'eth0',
                                          'Subnet': IPv4Network(
                                              f'{cyborg.environment_controller.hostname_ip_map[hostname]}/28', False)}],
                           'Sessions': [{'Agent': 'Red',
                                         'ID': count,
                                         'Type': SessionType.RED_REVERSE_SHELL,
                                         'Username': 'root'}]},
                'success': TrinaryEnum.TRUE}
            reward += 0.1
            temp_reward = reward
            count += 1
        else:
            raise ValueError
        red_privilege_escalate(expected_observation, hostname, temp_reward)

    # recon hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        temp_reward = reward
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            temp_reward = reward-0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4'] \
                or address == lo:
            continue
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise0']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]}]},
                                    'success': TrinaryEnum.TRUE}
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise1']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 135}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 3389}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 445}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 139}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 80}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 443}]}]},
                                    'success': TrinaryEnum.TRUE}
        else:
            raise ValueError
        red_remote_service_discover(expected_observation, address, temp_reward)

    # exploit hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        temp_reward = reward
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            temp_reward = reward -0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4'] \
                or address == lo:
            continue
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise0']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': 22,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.SSH},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 22,
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': LinuxEphemeralPort()}],
                                                                  'Process Type': ProcessType.SSH},
                                                                 ],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.SSH,
                                                                 'Username': 'pi'}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.LINUX},
                                                   'User Info': [{'Password': 'raspberry',
                                                                  'UID': 1001,
                                                                  'Username': 'pi'}]
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': LinuxEphemeralPort(),
                                                                                    'remote_address': address,
                                                                                    'remote_port': 22}]}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
        elif address == cyborg.environment_controller.hostname_ip_map['Enterprise1']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': Win2008EphemeralPort(),
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 443,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.WEBSERVER}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.WINDOWS}
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': 4444,
                                                                                    'remote_address': address,
                                                                                    'remote_port': Win2008EphemeralPort()}],
                                                                   'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
        else:
            raise ValueError
        red_remote_service_exploit(expected_observation, address, temp_reward)

    # priv esc hosts in enterprise subnet
    enterprise_subnet = cyborg.environment_controller.subnet_cidr_map['Enterprise']
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 6
    for hostname in hostnames:
        temp_reward = reward
        # test if output of observation matches expected output
        if not action_space["hostname"][hostname]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            temp_reward = reward -0.1
        elif 'User' in hostname:
            continue
        elif hostname == 'Enterprise0':
            expected_observation = {hostname: {'Interface': [{'IP Address':
                                                                  cyborg.environment_controller.hostname_ip_map[
                                                                      hostname],
                                                              'Interface Name': 'eth0',
                                                              'Subnet': enterprise_subnet}],
                                               'Sessions': [{'Agent': 'Red',
                                                             'ID': count,
                                                             'Type': SessionType.SSH,
                                                             'Username': 'root'}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
            reward += 1
            temp_reward = reward
        elif hostname == 'Enterprise1':
            expected_observation = {hostname: {'Interface': [{'IP Address':
                                                                  cyborg.environment_controller.hostname_ip_map[
                                                                      hostname],
                                                              'Interface Name': 'eth0',
                                                              'Subnet': enterprise_subnet}],
                                               'Sessions': [{'Agent': 'Red',
                                                             'ID': count,
                                                             'Type': SessionType.RED_REVERSE_SHELL,
                                                             'Username': 'SYSTEM'}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1
            reward += 1
            temp_reward = reward
        else:
            raise ValueError
        red_privilege_escalate(expected_observation, hostname, temp_reward)

    # scan enterprise subnet
    action_space = cyborg.get_action_space('Red')
    assert enterprise_subnet in action_space['subnet']
    assert action_space['subnet'][enterprise_subnet]
    expected_observation = {str(cyborg.environment_controller.hostname_ip_map['Enterprise0']): {
        'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise0'],
                       'Subnet': enterprise_subnet}]},
        str(cyborg.environment_controller.hostname_ip_map['Enterprise1']): {'Interface': [
            {'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise1'],
             'Subnet': enterprise_subnet}]},
        str(cyborg.environment_controller.hostname_ip_map['Enterprise2']): {'Interface': [
            {'IP Address': cyborg.environment_controller.hostname_ip_map['Enterprise2'],
             'Subnet': enterprise_subnet}]},
        str(cyborg.environment_controller.hostname_ip_map['Defender']): {
            'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Defender'],
                           'Subnet': enterprise_subnet}]},
        'success': TrinaryEnum.TRUE}
    red_remote_system_discover(expected_observation, enterprise_subnet, reward)

    # scan the third enterprise host
    enterprise2_ip = cyborg.environment_controller.hostname_ip_map['Enterprise2']
    assert enterprise2_ip in action_space['ip_address']
    assert action_space['ip_address'][enterprise2_ip]
    expected_observation = {str(enterprise2_ip): {'Interface': [{'IP Address': enterprise2_ip}],
                                                  'Processes': [{'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 22}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 135}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 3389}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 445}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 139}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 80}]},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 443}]}]},
                            'success': TrinaryEnum.TRUE}
    red_remote_service_discover(expected_observation, enterprise2_ip, reward)

    # exploit the 3rd enterprise host
    expected_observation = {str(enterprise2_ip): {'Interface': [{'IP Address': enterprise2_ip}],
                                                  'Processes': [{'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': Win2008EphemeralPort(),
                                                                                  'remote_address':
                                                                                      cyborg.environment_controller.hostname_ip_map[
                                                                                          'User0'],
                                                                                  'remote_port': 4444}],
                                                                 'Process Type': ProcessType.REVERSE_SESSION},
                                                                {'Connections': [{'local_address': enterprise2_ip,
                                                                                  'local_port': 443,
                                                                                  'Status': ProcessState.OPEN}],
                                                                 'Process Type': ProcessType.WEBSERVER}],
                                                  'Sessions': [{'Agent': 'Red',
                                                                'ID': 8,
                                                                'Type': SessionType.RED_REVERSE_SHELL}],
                                                  'System info': {'Hostname': 'Enterprise2',
                                                                  'OSType': OperatingSystemType.WINDOWS}},
                            str(cyborg.environment_controller.hostname_ip_map['User0']): {
                                'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['User0']}],
                                'Processes': [{'Connections': [
                                    {'local_address': cyborg.environment_controller.hostname_ip_map['User0'],
                                     'local_port': 4444,
                                     'remote_address': enterprise2_ip,
                                     'remote_port': Win2008EphemeralPort()}],
                                    'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                            'success': TrinaryEnum.TRUE}
    red_remote_service_exploit(expected_observation, enterprise2_ip, reward)

    # priv esc on enterprise host
    assert 'Enterprise2' in action_space['hostname']
    assert action_space['hostname']['Enterprise2']
    expected_observation = {
        'Op_Server0': {'Interface': [{'IP Address': cyborg.environment_controller.hostname_ip_map['Op_Server0']}]},
        'Enterprise2': {'Interface': [{'IP Address': enterprise2_ip,
                                       'Interface Name': 'eth0',
                                       'Subnet': enterprise_subnet}],
                        'Sessions': [{'Agent': 'Red',
                                      'ID': 8,
                                      'Type': SessionType.RED_REVERSE_SHELL,
                                      'Username': 'SYSTEM'}]},
        'success': TrinaryEnum.TRUE}
    reward += 1
    red_privilege_escalate(expected_observation, 'Enterprise2', reward)

    # scan the op server
    op_server_ip = cyborg.environment_controller.hostname_ip_map['Op_Server0']
    assert op_server_ip in action_space['ip_address']
    assert action_space['ip_address'][op_server_ip]
    expected_observation = {str(op_server_ip): {'Interface': [{'IP Address': op_server_ip}],
                                                'Processes': [{'Connections': [{'local_address': op_server_ip,
                                                                                'local_port': 22}]}]},
                            'success': TrinaryEnum.TRUE}
    red_remote_service_discover(expected_observation, op_server_ip, reward)

    # exploit the op server
    count = 9
    action = ExploitRemoteService(agent='Red', ip_address=op_server_ip, session=session)
    result = cyborg.step('Red', action)
    expected_observation = {str(op_server_ip): {'Interface': [{'IP Address': op_server_ip}],
                                                'Processes': [{'Connections': [{'local_address': op_server_ip,
                                                                                'local_port': 22,
                                                                                'Status': ProcessState.OPEN}],
                                                               'Process Type': ProcessType.SSH},
                                                              {'Connections': [{'local_address': op_server_ip,
                                                                                'local_port': 22,
                                                                                'remote_address': initial_ip_address,
                                                                                'remote_port': LinuxEphemeralPort()}],
                                                               'Process Type': ProcessType.SSH},
                                                              ],
                                                'Sessions': [{'Agent': 'Red',
                                                              'ID': count,
                                                              'Type': SessionType.SSH,
                                                              'Username': 'pi'}],
                                                'System info': {'Hostname': {v: i for i, v in
                                                                             cyborg.environment_controller.hostname_ip_map.items()}[
                                                    op_server_ip],
                                                                'OSType': OperatingSystemType.LINUX},
                                                'User Info': [{'Password': 'raspberry',
                                                               'UID': 1001,
                                                               'Username': 'pi'}]
                                                },
                            str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                      'Processes': [
                                                          {'Connections': [{'local_address': initial_ip_address,
                                                                            'local_port': LinuxEphemeralPort(),
                                                                            'remote_address': op_server_ip,
                                                                            'remote_port': 22}]}]},
                            'success': TrinaryEnum.TRUE}
    assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
    assert not result.done
    assert result.observation == expected_observation, f'Incorrect observation for scan of enterprise subnet'

    # try and impact before priv esc
    action = Impact(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.FALSE}
    assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
    assert not result.done
    assert result.observation == expected_observation, f'Incorrect observation for scan of enterprise subnet'

    # priv esc on op server
    op_server_subnet = cyborg.environment_controller.subnet_cidr_map['Operational']
    assert 'Op_Server0' in action_space['hostname']
    assert action_space['hostname']['Op_Server0']
    action = PrivilegeEscalate(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'Op_Server0': {'Interface': [{'IP Address': op_server_ip,
                                                          'Interface Name': 'eth0',
                                                          'Subnet': op_server_subnet}],
                                           'Processes': [{'PID': 1043, 'Service Name': 'OTService'}],
                                           'Sessions': [{'Agent': 'Red',
                                                         'ID': count,
                                                         'Type': SessionType.SSH,
                                                         'Username': 'root'}]},
                            'success': TrinaryEnum.TRUE}
    reward += 1
    assert result.reward == round(reward, REWARD_MAX_DECIMAL_PLACES)
    assert not result.done
    assert result.observation == expected_observation, f'Incorrect observation for scan of enterprise subnet'

    action = Impact(agent='Red', hostname='Op_Server0', session=session)
    result = cyborg.step('Red', action)
    expected_observation = {'success': TrinaryEnum.TRUE}
    assert result.reward == round(reward+10, REWARD_MAX_DECIMAL_PLACES)
    assert not result.done
    assert result.observation == expected_observation, f'Incorrect observation for scan of enterprise subnet'

@pytest.mark.skip
def test_port_scan():
    # create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    # test discover remote systems
    # act on all subnets in action space
    action_space = cyborg.get_action_space('Red')
    initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]

    def red_remote_system_discover(expected_observation, subnet, reward):
        action = DiscoverRemoteSystems(subnet=subnet, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation, f'failed scan of {subnet}'

    def red_remote_service_discover(expected_observation, ip_address, reward):
        action = DiscoverNetworkServices(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation

    def red_remote_service_exploit(expected_observation, ip_address, reward):
        action = ExploitRemoteService(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation
    cumm_reward = 0
    for subnet in action_space["subnet"]:
        if not action_space["subnet"][subnet]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1
        else:
            expected_observation = {str(cyborg.environment_controller.hostname_ip_map['User' + str(i)]): {'Interface':
                [{
                    'IP Address':
                        cyborg.environment_controller.hostname_ip_map[
                            'User' + str(
                                i)],
                    'Subnet': subnet}]}
                for i in range(5)}
            reward = 0
            expected_observation.update({'success': True})
        red_remote_system_discover(expected_observation, subnet, reward)

    # test discover network services
    # act on ip addresses discovered in first subnet
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 135}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 3389}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 445}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 139}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = 0
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 80}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = 0
        else:
            raise ValueError
        red_remote_service_discover(expected_observation, address, reward)

    # test exploit action by acting on all known ip_addresses
    count = 1
    initial_ip_address = initial_observation['User0']['Interface'][0]['IP Address']
    # own all hosts on the client subnet
    for address in addresses:
        reward = cumm_reward
        # test if output of observation matches expected output
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1 + cumm_reward
        elif address == initial_ip_address:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': 4444,
                                                                                   'remote_address': address,
                                                                                   'remote_port': Win2008EphemeralPort()}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION_HANDLER},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': Win2008EphemeralPort(),
                                                                                   'remote_address': address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 139,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.SMB}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': 'User0',
                                                                   'OSType': OperatingSystemType.WINDOWS}
                                                   },
                                    'success': TrinaryEnum.TRUE}
            count += 1
        elif address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': Win2008EphemeralPort(),
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 139,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.SMB}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.WINDOWS}
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': 4444,
                                                                                    'remote_address': address,
                                                                                    'remote_port': Win2008EphemeralPort()}],
                                                                   'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                                    'success': TrinaryEnum.TRUE}
            cumm_reward += 0.1
            reward = cumm_reward
            count += 1
        elif address == \
                cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [{'Connections': [{'local_address': address,
                                                                                   'local_port': LinuxEphemeralPort(),
                                                                                   'remote_address': initial_ip_address,
                                                                                   'remote_port': 4444}],
                                                                  'Process Type': ProcessType.REVERSE_SESSION},
                                                                 {'Connections': [{'local_address': address,
                                                                                   'local_port': 80,
                                                                                   'Status': ProcessState.OPEN}],
                                                                  'Process Type': ProcessType.WEBSERVER}],
                                                   'Sessions': [{'Agent': 'Red',
                                                                 'ID': count,
                                                                 'Type': SessionType.RED_REVERSE_SHELL}],
                                                   'System info': {'Hostname': {v: i for i, v in
                                                                                cyborg.environment_controller.hostname_ip_map.items()}[
                                                       address],
                                                                   'OSType': OperatingSystemType.LINUX}
                                                   },
                                    str(initial_ip_address): {'Interface': [{'IP Address': initial_ip_address}],
                                                              'Processes': [
                                                                  {'Connections': [{'local_address': initial_ip_address,
                                                                                    'local_port': 4444,
                                                                                    'remote_address': address,
                                                                                    'remote_port': LinuxEphemeralPort()}],
                                                                   'Process Type': ProcessType.REVERSE_SESSION_HANDLER}]},
                                    'success': TrinaryEnum.TRUE}
            count += 1

        else:
            raise NotImplementedError

        red_remote_service_exploit(expected_observation, address, reward)

    # test discover network services still returns same values as before
    # act on ip addresses discovered in first subnet
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = -0.1 + cumm_reward
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] or address == \
                cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 135}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 3389}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 445}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 139}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = cumm_reward
        elif address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
            expected_observation = {str(address): {'Interface': [{'IP Address': address}],
                                                   'Processes': [
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 22}]},
                                                       {'Connections': [{'local_address': address,
                                                                         'local_port': 80}]}]},
                                    'success': TrinaryEnum.TRUE}
            reward = cumm_reward
        else:
            raise ValueError
        red_remote_service_discover(expected_observation, address, reward)
    
