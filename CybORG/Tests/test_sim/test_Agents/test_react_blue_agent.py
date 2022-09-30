import inspect
from ipaddress import IPv4Network

from CybORG import CybORG
from CybORG.Agents.SimpleAgents.BlueReactAgent import BlueReactRemoveAgent
from CybORG.Shared.Actions import Impact, PrivilegeEscalate, ExploitRemoteService, DiscoverNetworkServices, \
    DiscoverRemoteSystems
from CybORG.Shared.Enums import TrinaryEnum, SessionType, ProcessType, ProcessState, OperatingSystemType
from CybORG.Tests.EphemeralPort import LinuxEphemeralPort, Win2008EphemeralPort, PID
import pytest


@pytest.mark.skip()
@pytest.mark.parametrize("seed", [1])
def test_react_blue_agent(seed):
    # create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents={'Blue': BlueReactRemoveAgent})
    cyborg.set_seed(seed)

    # test discover remote systems
    # act on all subnets in action space
    action_space = cyborg.get_action_space('Red')
    initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]

    def red_remote_system_discover(expected_observation, subnet, reward):
        action = DiscoverRemoteSystems(subnet=subnet, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        # assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation, f'failed scan of {subnet}'

    def red_remote_service_discover(expected_observation, ip_address, reward):
        action = DiscoverNetworkServices(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        # assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation

    def red_remote_service_exploit(expected_observation, ip_address, reward):
        action = ExploitRemoteService(ip_address=ip_address, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        # assert result.reward == reward
        assert not result.done
        assert result.observation == expected_observation

    def red_privilege_escalate(expected_observation, hostname, reward):
        action = PrivilegeEscalate(hostname=hostname, agent='Red', session=session)
        result = cyborg.step(action=action, agent='Red')
        # test if output of observation matches expected output
        # assert result.reward == round(reward, 1), f'incorrect reward for host {hostname}'
        assert not result.done
        assert result.observation == expected_observation

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
    cumm_reward = 0
    for address in addresses:
        reward = cumm_reward
        # test if output of observation matches expected output
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward += -0.1
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
            count += 1
            cumm_reward += 0.1
            reward = cumm_reward
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

    # priv esc on all hosts in client subnet
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 2
    for hostname in hostnames:
        reward = cumm_reward
        # test if output of observation matches expected output
        if not action_space["hostname"][hostname]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward += -0.1
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
        elif hostname == 'User3' or hostname == 'User4':
            if seed in [] or hostname == 'User4':
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
                reward = cumm_reward
            else:
                expected_observation = {'success': False}
                reward = cumm_reward
            reward += 0.1 if hostname == 'User4' else 0
            count += 1
        else:
            raise ValueError
        red_privilege_escalate(expected_observation, hostname, reward)

    # recon hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        reward = cumm_reward
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = cumm_reward-0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
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
        red_remote_service_discover(expected_observation, address, reward)


    # exploit hosts in enterprise subnet
    action_space = cyborg.get_action_space('Red')
    addresses = [i for i in action_space["ip_address"]]
    for address in addresses:
        reward = cumm_reward
        if not action_space["ip_address"][address]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = cumm_reward-0.1
        elif address == cyborg.environment_controller.hostname_ip_map['User0'] \
                or address == cyborg.environment_controller.hostname_ip_map['User1'] \
                or address == cyborg.environment_controller.hostname_ip_map['User2'] \
                or address == cyborg.environment_controller.hostname_ip_map['User3'] \
                or address == cyborg.environment_controller.hostname_ip_map['User4']:
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
        red_remote_service_exploit(expected_observation, address, reward)

    # priv esc hosts in enterprise subnet
    enterprise_subnet = cyborg.environment_controller.subnet_cidr_map['Enterprise']
    action_space = cyborg.get_action_space('Red')
    hostnames = action_space['hostname']
    count = 6
    for hostname in hostnames:
        reward = cumm_reward
        # test if output of observation matches expected output
        if not action_space["hostname"][hostname]:
            expected_observation = {'success': TrinaryEnum.FALSE}
            reward = cumm_reward-0.1
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
            reward = 1
        elif hostname == 'Enterprise1':
            if seed in []:
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
                reward = 1
            else:
                expected_observation = {'success': TrinaryEnum.FALSE}
                count += 1
        else:
            raise ValueError
        red_privilege_escalate(expected_observation, hostname, reward)
