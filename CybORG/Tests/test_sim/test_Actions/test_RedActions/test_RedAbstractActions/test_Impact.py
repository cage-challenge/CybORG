# TODO fix tests to not use scop=module
# import pytest
# import itertools
# from copy import deepcopy
#
# from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
# from CybORG.Agents.Utils import ObservationWrapper
# from CybORG.Simulator.Actions import Impact, Impact
# from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
# from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort
#
# SCENARIO = 'Scenario2'
# HOSTS = SCENARIOS[SCENARIO]['Hosts']
# VULNERABLE_HOSTS = ['Op_Server0']
# OS_MAP = SCENARIOS[SCENARIO]['OS_Map']
#
# EXPLOIT_PARAMETERS = ['session', 'agent', 'hostname']
#
# @pytest.fixture(scope='module')
# def source_host():
#     return 'User0'
#
# @pytest.fixture(scope='module')
# def source_ip(cyborg):
#     return cyborg.get_ip_map()['User0']
#
# @pytest.fixture(params=HOSTS, scope='module')
# def target_host(request):
#     return request.param
#
# @pytest.fixture(scope='module')
# def target_ip(cyborg, target_host):
#     return cyborg.get_ip_map()[target_host]
#
# @pytest.fixture(scope='module')
# def cyborg(target_host):
#     return compromised_cyborg(SCENARIO, stop_host='Op_Server0', stop_value=3)
#
# @pytest.fixture(scope='module')
# def action(target_host, cyborg):
#     return Impact(hostname=target_host, agent='Red', session=0)
#
# @pytest.fixture(scope='module')
# def observation(cyborg, action):
#     results = cyborg.step(action=action, agent='Red')
#
#     return ObservationWrapper(results.observation)
#
# def test_Impact_success(observation, target_host):
#     assert observation.success == (True if target_host in VULNERABLE_HOSTS else False)
#
# @pytest.fixture()
# def expected_num_hosts(target_host):
#     if target_host == 'Op_Server0':
#         return 0
#
#     return 1 if target_host in VULNERABLE_HOSTS else 0
#
# def test_Impact_num_hosts(observation, expected_num_hosts):
#     assert len(observation.hosts) == expected_num_hosts
#
# def test_Impact_target_interfaces(observation, target_ip, target_host):
#     interface = []
#     expected_interface = interface if target_host in VULNERABLE_HOSTS else []
#
#     assert observation.get_interfaces(target_ip) == expected_interface
#
# def test_Impact_target_processes(observation, target_ip, target_host, source_ip):
#     processes = []
#     expected_processes = processes if target_host in VULNERABLE_HOSTS else []
#
#     assert observation.get_processes(target_ip) == expected_processes
#
# def test_Impact_target_sessions(observation, target_ip, target_host, cyborg):
#     sessions = []
#     expected_sessions = sessions if target_host in VULNERABLE_HOSTS else []
#
#     assert observation.get_sessions(target_ip) == expected_sessions
#
# def test_Impact_target_os_info(observation, target_ip, target_host):
#     os_info = {}
#
#     expected_os_info = os_info if target_host in VULNERABLE_HOSTS else {}
#
#     assert observation.get_os_info(target_ip) == expected_os_info
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
# def test_Impact_junk_input_observation(junk_observation, junk_action):
#     assert junk_observation == {'success':TrinaryEnum.UNKNOWN}
#
# @pytest.fixture(scope='module')
# def last_action(cyborg, junk_observation):
#     # Junk observation required to ensure cyborg actually executes junk action
#     return cyborg.get_last_action('Red')
#
# def test_Impact_junk_input_action(last_action):
#     assert last_action.name == 'InvalidAction'
#
# def test_Impact_junk_input_replaced_action(last_action, junk_action):
#     assert getattr(last_action, 'action') == junk_action
#
# def test_Impact_unscanned(cyborg, target_host, action):
#     cyborg.reset()
#     target_ip = cyborg.get_ip_map()[target_host]
#     action = Impact(hostname=target_host, agent='Red', session=0)
#     results = cyborg.step(action=action, agent='Red')
#
#     assert results.observation == {'success': TrinaryEnum.UNKNOWN}
#
