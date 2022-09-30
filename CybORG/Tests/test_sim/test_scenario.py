from CybORG.Shared.Actions import PrivilegeEscalate, MS17_010_PSExec, UpgradeToMeterpreter, SSHLoginExploit, \
    MeterpreterIPConfig, MSFAutoroute, MSFPingsweep, MSFPortscan, GetFileInfo, GetProcessList, GetProcessInfo, \
    VelociraptorPoll, GetLocalGroups, GetUsers, GetOSInfo, Sleep, Impact, Monitor, Analyse, Restore, Remove, \
    DiscoverNetworkServices, DiscoverRemoteSystems, ExploitRemoteService, Misinform

import pytest

def test_scenario_action_space(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    # check that the action space and observation space for each agent is correct
    # set up expect action spaces for each agent
    if scenario == 'Scenario1b':
        def get_expected_action_space(cyborg_obj):
            expected_action_space = {'Red': {'action': {Sleep: True,
                                                        DiscoverRemoteSystems: True,
                                                        DiscoverNetworkServices: True,
                                                        ExploitRemoteService: True,
                                                        PrivilegeEscalate: True,
                                                        Impact: True},
                                             'subnet': {cyborg_obj.environment_controller.subnet_cidr_map['User']: True,
                                                        cyborg_obj.environment_controller.subnet_cidr_map[
                                                            'Enterprise']: False,
                                                        cyborg_obj.environment_controller.subnet_cidr_map[
                                                            'Operational']: False},
                                             'ip_address': {
                                                 cyborg_obj.environment_controller.hostname_ip_map['User0']: True,
                                                 cyborg_obj.environment_controller.hostname_ip_map['User1']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map['User2']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map['User3']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map['User4']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Enterprise0']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Enterprise1']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Enterprise2']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Defender']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Op_Host0']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Op_Host1']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Op_Host2']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Op_Server0']: False
                                                 },
                                             'port': {22: False,
                                                      80: False,
                                                      135: False,
                                                      139: False,
                                                      443: False,
                                                      445: False,
                                                      3389: False
                                                      },
                                             'hostname': {'User0': True,
                                                          'User1': False,
                                                          'User2': False,
                                                          'User3': False,
                                                          'User4': False,
                                                          'Enterprise0': False,
                                                          'Enterprise1': False,
                                                          'Enterprise2': False,
                                                          'Defender': False,
                                                          'Op_Host0': False,
                                                          'Op_Host1': False,
                                                          'Op_Host2': False,
                                                          'Op_Server0': False
                                                          },
                                             'username': {'Administrator': False,
                                                          'GreenAgent': False,
                                                          'SYSTEM': False,
                                                          'pi': False,
                                                          'root': False,
                                                          'ubuntu': False,
                                                          'vagrant': False,
                                                          'www-data': False},
                                             'password': {'raspberry': False, 'vagrant': False},
                                             'target_session': {0: False,
                                                                1: False,
                                                                2: False,
                                                                3: False,
                                                                4: False,
                                                                5: False,
                                                                6: False,
                                                                7: False},
                                             },
                                     'Blue': {'action': {Sleep: True,
                                                         Monitor: True,
                                                         Analyse: True,
                                                         Remove: True,
                                                         Misinform: True,
                                                         Restore: True},
                                              'subnet': {cyborg_obj.environment_controller.subnet_cidr_map['User']: True,
                                                         cyborg_obj.environment_controller.subnet_cidr_map[
                                                             'Enterprise']: True,
                                                         cyborg_obj.environment_controller.subnet_cidr_map[
                                                             'Operational']: True},
                                              'ip_address': {
                                                  cyborg_obj.environment_controller.hostname_ip_map['User0']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map['User1']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map['User2']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map['User3']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map['User4']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Enterprise0']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Enterprise1']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Enterprise2']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Defender']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Op_Host0']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Op_Host1']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Op_Host2']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Op_Server0']: True
                                                  },
                                              'port': {22: False,
                                                       80: False,
                                                       135: False,
                                                       139: False,
                                                       443: False,
                                                       445: False,
                                                       3389: False
                                                       },
                                              'hostname': {'User0': True,
                                                           'User1': True,
                                                           'User2': True,
                                                           'User3': True,
                                                           'User4': True,
                                                           'Enterprise0': True,
                                                           'Enterprise1': True,
                                                           'Enterprise2': True,
                                                           'Defender': True,
                                                           'Op_Host0': True,
                                                           'Op_Host1': True,
                                                           'Op_Host2': True,
                                                           'Op_Server0': True
                                                           },
                                              'username': {'Administrator': True,
                                                           'GreenAgent': True,
                                                           'SYSTEM': True,
                                                           'pi': True,
                                                           'root': True,
                                                           'ubuntu': True,
                                                           'vagrant': True,
                                                           'www-data': True},
                                              'password': {'raspberry': True, 'vagrant': True},
                                              'target_session': {0: False,
                                                                 1: True,
                                                                 2: True,
                                                                 3: True,
                                                                 4: True,
                                                                 5: True,
                                                                 6: True,
                                                                 7: True,
                                                                 8: True,
                                                                 9: True,
                                                                 10: True,
                                                                 11: True,
                                                                 12: True,
                                                                 13: True},
                                              },
                                     'Green': {}}
            return expected_action_space
    elif scenario == 'Scenario1':
        def get_expected_action_space(cyborg_obj):
            expected_action_space = {'Red': {'action': {MS17_010_PSExec: True,
                                                        UpgradeToMeterpreter: True,
                                                        Sleep: True,
                                                        SSHLoginExploit: True,
                                                        MeterpreterIPConfig: True,
                                                        MSFAutoroute: True,
                                                        MSFPortscan: True,
                                                        MSFPingsweep: True},
                                             'subnet': {
                                                 cyborg_obj.environment_controller.subnet_cidr_map[
                                                     'Attacker_Network']: True,
                                                 cyborg_obj.environment_controller.subnet_cidr_map['Private_Network']: True,
                                                 cyborg_obj.environment_controller.subnet_cidr_map[
                                                     'Defender_Network']: False},
                                             'ip_address': {
                                                 cyborg_obj.environment_controller.hostname_ip_map['Attacker']: True,
                                                 cyborg_obj.environment_controller.hostname_ip_map['Gateway']: True,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Internal']: False,
                                                 cyborg_obj.environment_controller.hostname_ip_map[
                                                     'Defender']: False},
                                             'port': {22: False,
                                                      68: False,
                                                      80: False,
                                                      135: False,
                                                      139: False,
                                                      443: False,
                                                      445: False,
                                                      3389: False,
                                                      55553: False
                                                      },
                                             'hostname': {'Attacker': True,
                                                          'Gateway': False,
                                                          'Internal': False,
                                                          'Defender': False},
                                             'username': {'Administrator': False,
                                                          'GreenAgent': False,
                                                          'SYSTEM': False,
                                                          'ec2-user': False,
                                                          'pi': False,
                                                          'root': False,
                                                          'ubuntu': False,
                                                          'vagrant': False,
                                                          'www-data': False},
                                             'password': {'raspberry': False, 'vagrant': False},
                                             'target_session': {0: False,
                                                                1: False,
                                                                2: False,
                                                                3: False,
                                                                4: False,
                                                                5: False,
                                                                6: False,
                                                                7: False},
                                             },
                                     'Blue': {'action': {Sleep: True,
                                                         GetProcessList: True,
                                                         GetProcessInfo: True,
                                                         VelociraptorPoll: True,
                                                         GetLocalGroups: True,
                                                         GetFileInfo: True,
                                                         GetUsers: True,
                                                         GetOSInfo: True},
                                              'subnet': {
                                                  cyborg_obj.environment_controller.subnet_cidr_map[
                                                      'Attacker_Network']: False,
                                                  cyborg_obj.environment_controller.subnet_cidr_map[
                                                      'Private_Network']: True,
                                                  cyborg_obj.environment_controller.subnet_cidr_map[
                                                      'Defender_Network']: True},
                                              'ip_address': {
                                                  cyborg_obj.environment_controller.hostname_ip_map['Attacker']: False,
                                                  cyborg_obj.environment_controller.hostname_ip_map['Gateway']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Internal']: True,
                                                  cyborg_obj.environment_controller.hostname_ip_map[
                                                      'Defender']: True},
                                              'port': {22: False,
                                                       68: False,
                                                       80: False,
                                                       135: False,
                                                       139: False,
                                                       443: False,
                                                       445: False,
                                                       3389: False,
                                                       55553: False
                                                       },
                                              'hostname': {'Attacker': False,
                                                           'Gateway': True,
                                                           'Internal': True,
                                                           'Defender': True},
                                              'username': {'Administrator': False,
                                                           'GreenAgent': False,
                                                           'SYSTEM': False,
                                                           'ec2-user': False,
                                                           'pi': False,
                                                           'root': False,
                                                           'ubuntu': False,
                                                           'vagrant': False,
                                                           'www-data': False},
                                              'password': {'raspberry': False, 'vagrant': False},
                                              'target_session': {0: False,
                                               1: True,
                                               2: True,
                                               3: False,
                                               4: False,
                                               5: False,
                                               6: False,
                                               7: False},
                                     },
                                     'Green': {'action': {},
                                              'subnet': {},
                                              'ip_address': {},
                                              'port': {},
                                              'hostname': {},
                                              'username': {},
                                              'password': {}
                                              }}
            return expected_action_space
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')
    expected_action_space = get_expected_action_space(cyborg)
    for agent in ['Red', 'Blue']:  # TODO add back in green agent tests, 'Green']:
        action_space = cyborg.get_action_space(agent)
        assert action_space['agent'] == {agent: True}, f'incorrect action space for {agent}'
        assert action_space['action'] == expected_action_space[agent]['action'], f'incorrect action space for {agent}'
        assert action_space['subnet'] == expected_action_space[agent]['subnet'], f'incorrect action space for {agent}'
        assert action_space['ip_address'] == expected_action_space[agent]['ip_address'], f'incorrect action space for {agent}'
        # assert action_space['port'] == expected_action_space[agent]['port'], f'incorrect action space for {agent}'
        assert action_space['hostname'] == expected_action_space[agent]['hostname'], f'incorrect action space for {agent}'
        assert action_space['password'] == expected_action_space[agent]['password'], f'incorrect action space for {agent}'
        assert action_space['username'] == expected_action_space[agent]['username'], f'incorrect action space for {agent}'
        assert action_space['session'] == {0: True}, f'incorrect action space for {agent}'
        # assert action_space['target_session'] == expected_action_space[agent]['target_session'], f'incorrect action space for {agent}'
    cyborg.reset()
    expected_action_space = get_expected_action_space(cyborg)
    for agent in ['Red', 'Blue']:  # TODO add back in green agent tests, 'Green']:
        action_space = cyborg.get_action_space(agent)
        assert action_space['agent'] == {agent: True}, f'incorrect action space for {agent}'
        assert action_space['action'] == expected_action_space[agent]['action'], f'incorrect action space for {agent}'
        assert action_space['subnet'] == expected_action_space[agent]['subnet'], f'incorrect action space for {agent}'
        assert action_space['ip_address'] == expected_action_space[agent][
            'ip_address'], f'incorrect action space for {agent}'
        # assert action_space['port'] == expected_action_space[agent]['port'], f'incorrect action space for {agent}'
        assert action_space['hostname'] == expected_action_space[agent][
            'hostname'], f'incorrect action space for {agent}'
        assert action_space['password'] == expected_action_space[agent][
            'password'], f'incorrect action space for {agent}'
        assert action_space['username'] == expected_action_space[agent][
            'username'], f'incorrect action space for {agent}'
        assert action_space['session'] == {0: True}, f'incorrect action space for {agent}'
        # assert action_space['target_session'] == expected_action_space[agent][
            # 'target_session'], f'incorrect action space for {agent}'


# TODO: implement the observation space function
@pytest.mark.skip('Unimplemented Observation space function')
def test_scenario_observation_space(create_cyborg_sim):
    # create cyborg environment
    cyborg, scenario = create_cyborg_sim
    # check that the action space and observation space for each agent is correct
    # set up expect action spaces for each agent
    expected_obs_space = {'Red': [],
                          'Blue': [],
                          'Green': []}
    for agent in ['Red', 'Blue', 'Green']:
        obs_space = cyborg.get_observation_space(agent)
        assert obs_space == expected_obs_space[agent]
