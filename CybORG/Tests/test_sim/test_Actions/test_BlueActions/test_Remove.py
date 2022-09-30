# TODO fix tests to not use scop=module
# import pytest
# import itertools
# from copy import deepcopy
#
# from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
# from CybORG.Agents.Utils import ObservationWrapper
# from CybORG.Simulator.Actions import Remove, ExploitRemoteService, PrivilegeEscalate
# from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
# from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort
#
# SCENARIO = 'Scenario2'
# HOSTS = SCENARIOS[SCENARIO]['Hosts']
#
# EXPLOIT_PARAMETERS = ['session', 'agent', 'hostname']
#
# @pytest.fixture(params=HOSTS, scope='module')
# def target_host(request):
#     return request.param
#
# @pytest.fixture(scope='function')
# def cyborg(target_host):
#     return compromised_cyborg(SCENARIO, stop_host=target_host, stop_value=2)
#
# @pytest.fixture(scope='module')
# def action(target_host):
#     return Remove(hostname=target_host, session=0, agent='Blue')
#
# @pytest.fixture(scope='module')
# def observation(cyborg, action):
#     results = cyborg.step(action=action, agent='Blue')
#
#     return ObservationWrapper(results.observation)
#
# def test_Remove_success(observation, target_host):
#     assert observation.success == True
#
# def test_Remove_num_hosts(observation, target_host):
#     assert len(observation.hosts) == 0
#
# @pytest.mark.skip(reason='Only works if exploit doesn\'t give root shell.')
# def test_Remove_prevents_privesc(cyborg, observation, target_host):
#     action = PrivilegeEscalate(hostname=target_host, session=0, agent='Red')
#     results = cyborg.step(action=action, agent='Red')
#
#     assert results.observation['success'] == (False if target_host != 'User0' else True)
#
# @pytest.fixture(scope='module')
# def target_ip(cyborg, target_host):
#     return cyborg.get_ip_map()[target_host]
#
# def test_Remove_allows_exploit(cyborg, target_host, target_ip):
#     for i in range(100):
#         print(i)
#         red_action = ExploitRemoteService(ip_address=target_ip, session=0, agent='Red')
#         results = cyborg.step(action=red_action, agent='Red')
#
#         # TODO Remove USer0 from False list by ensuring it is actually scanned
#         # TODO check random failures of User3, Enterprise1 and Enterprise2 on i = 0 or 1
#         expected_success = True if target_host not in ('User0', 'Defender') else False
#         assert cyborg.environment_controller.test_valid_action(red_action, cyborg.environment_controller.agent_interfaces['Red'])
#         assert results.observation['success'] == expected_success, cyborg.environment_controller.observation['Red'].raw
#
# @pytest.fixture(scope='module')
# def privesc_cyborg(target_host):
#     return compromised_cyborg(SCENARIO, stop_host=target_host, stop_value=3)
#
# def test_Remove_does_not_remove_root_shell(privesc_cyborg, target_host):
#     if target_host == 'Defender':
#         return
#     privesc_cyborg.step(action=action, agent='Blue')
#     red_action = PrivilegeEscalate(hostname=target_host, session=0, agent='Red')
#     results = privesc_cyborg.step(action=red_action, agent='Red')
#
#     assert results.observation['success'] == True
#
# @pytest.fixture(params=EXPLOIT_PARAMETERS, scope='module')
# def junk_action(action, request):
#     junk_action = deepcopy(action)
#     setattr(junk_action, request.param, 'Junk')
#
#     return junk_action
#
# @pytest.fixture(scope='module')
# def junk_observation(cyborg, junk_action):
#     results = cyborg.step(action=junk_action, agent='Red')
#
#     return results.observation
#
# def test_Remove_junk_input_observation(junk_observation, junk_action):
#     assert junk_observation == {'success':TrinaryEnum.UNKNOWN}
#
# @pytest.fixture(scope='module')
# def last_action(cyborg, junk_observation):
#     # Junk observation required to ensure cyborg actually executes junk action
#     return cyborg.get_last_action('Red')
#
# def test_Remove_junk_input_action(last_action):
#     assert last_action.name == 'InvalidAction'
#
# def test_Remove_junk_input_replaced_action(last_action, junk_action):
#     assert getattr(last_action, 'action') == junk_action
#
# def test_Remove_unscanned(cyborg, target_host, action):
#     cyborg.reset()
#     action = Remove(hostname=target_host, agent='Red', session=0)
#     results = cyborg.step(action=action, agent='Red')
#
#     assert results.observation == {'success': TrinaryEnum.UNKNOWN}
