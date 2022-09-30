# TODO fix tests to not use scop=module
# import pytest
# import itertools
# from copy import deepcopy
#
# from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
# from CybORG.Agents.Utils import ObservationWrapper
# from CybORG.Simulator.Actions import Restore, ExploitRemoteService, PrivilegeEscalate
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
#     return compromised_cyborg(SCENARIO, stop_host=target_host, stop_value=4)
#
# @pytest.fixture(scope='module')
# def action(target_host):
#     return Restore(hostname=target_host, session=0, agent='Blue')
#
# @pytest.fixture(scope='module')
# def observation(cyborg, action):
#     results = cyborg.step(action=action, agent='Blue')
#
#     return ObservationWrapper(results.observation)
#
# def test_Restore_success(observation, target_host):
#     assert observation.success == True
#
# def test_Restore_num_hosts(observation, target_host):
#     assert len(observation.hosts) == 0
#
# def test_Restore_prevents_privesc(cyborg, target_host):
#     action = PrivilegeEscalate(hostname=target_host, session=0, agent='Red')
#     results = cyborg.step(action=action, agent='Red')
#
#     assert results.observation['success'] == (False if target_host != 'User0' else True)
#
# @pytest.fixture(scope='module')
# def target_ip(cyborg, target_host):
#     return cyborg.get_ip_map()[target_host]
#
# def test_Restore_allows_exploit(cyborg, target_host, target_ip):
#     for i in range(100):
#         action = ExploitRemoteService(ip_address=target_ip, session=0, agent='Red')
#         results = cyborg.step(action=action, agent='Red')
#
#         # TODO Remove USer0 from False list by ensuring it is actually scanned
#         assert results.observation['success'] == (True if target_host not in ('User0','Defender') else False)
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
# def test_Restore_junk_input_observation(junk_observation, junk_action):
#     assert junk_observation == {'success':TrinaryEnum.UNKNOWN}
#
# @pytest.fixture(scope='module')
# def last_action(cyborg, junk_observation):
#     # Junk observation required to ensure cyborg actually executes junk action
#     return cyborg.get_last_action('Red')
#
# def test_Restore_junk_input_action(last_action):
#     assert last_action.name == 'InvalidAction'
#
# def test_Restore_junk_input_replaced_action(last_action, junk_action):
#     assert getattr(last_action, 'action') == junk_action
#
# def test_Restore_unscanned(cyborg, target_host, action):
#     cyborg.reset()
#     action = Restore(hostname=target_host, agent='Red', session=0)
#     results = cyborg.step(action=action, agent='Red')
#
#     assert results.observation == {'success': TrinaryEnum.UNKNOWN}
