# import pytest
# import inspect
#
# from CybORG import CybORG
# from ipaddress import IPv4Address
# from CybORG.Shared.Actions import MSFPortscan, SSHLoginExploit, UpgradeToMeterpreter, ServicePersistenceWindows, \
#     MeterpreterReboot
# from CybORG.Shared.Enums import SessionType
# from CybORG.Simulator.LocalGroup import LocalGroup
# from CybORG.Simulator.User import User
# from collections import namedtuple
#
# from CybORG.Tests.EphemeralPort import LinuxEphemeralPort
# from CybORG.Tests.utils import PID
# import CybORG.Shared.Enums as CyEnums
#
#
# @pytest.fixture()
# def set_up_state():
#     path = str(inspect.getfile(CybORG))
#     path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
#     agent = 'Red'
#     cyborg = CybORG(path, 'sim')
#     address = IPv4Address(cyborg.environment_controller.state.hosts['Internal'].interfaces[1].ip_address)
#     action = MSFPortscan(ip_address=address, session=0, agent=agent)
#     result = cyborg.step(agent, action)
#     action = SSHLoginExploit(ip_address=address, agent=agent, session=0, port=22)
#     result = cyborg.step(agent, action)
#     action = UpgradeToMeterpreter(session=0, agent='Red', target_session=1)
#     result = cyborg.step(agent, action)
#     state = cyborg.environment_controller.state
#     return namedtuple("Setup", "state meterpreter_session")(state, 2, )
#
#
# @pytest.fixture()
# def set_up_state_admin(set_up_state):
#     # change the session owner to a user with admin
#     group = LocalGroup(name='ADMINISTRATORS')
#     admin_user = User(username='kylo_ren', uid=0)
#     admin_user.add_group(group)
#     target_host = set_up_state.state.hosts['Internal']
#
#     target_host.users.append(admin_user)
#     set_up_state.state.sessions['Red'][set_up_state.meterpreter_session].user = admin_user
#     return set_up_state
#
#
# @pytest.fixture()
# def set_up_state_linux():
#     path = str(inspect.getfile(CybORG))
#     path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
#     agent = 'Red'
#     cyborg = CybORG(path, 'sim')
#     address = IPv4Address(cyborg.environment_controller.state.hosts['Gateway'].interfaces[1].ip_address)
#     action = MSFPortscan(ip_address=address, session=0, agent=agent)
#     cyborg.step(agent, action)
#     action = SSHLoginExploit(ip_address=address, agent=agent, session=0, port=22)
#     cyborg.step(agent, action)
#     action = UpgradeToMeterpreter(session=0, agent='Red', target_session=1)
#     cyborg.step(agent, action)
#     state = cyborg.environment_controller.state
#
#     # change the session owner to a user with admin
#     group = LocalGroup(name='ADMINISTRATORS')
#     admin_user = User(username='kylo_ren', uid=0)
#     admin_user.add_group(group)
#     target_host = state.hosts['Internal']
#
#     target_host.users.append(admin_user)
#     state.sessions['Red'][2].user = admin_user
#     return namedtuple("Setup", "state meterpreter_session")(state, 2, )
#
#
# def test_on_non_admin(set_up_state):
#     # Change the session owner to a user without admin privileges
#     user = User(username='kylo_ren', uid=0)
#
#     set_up_state.state.hosts['Internal'].users.append(user)
#     set_up_state.state.sessions['Red'][set_up_state.meterpreter_session].user = user
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state.meterpreter_session)
#     observation = action.sim_execute(set_up_state.state)
#     assert observation.action_succeeded is False
#
#
# def test_os(set_up_state_linux):
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state_linux.meterpreter_session)
#     observation = action.sim_execute(set_up_state_linux.state)
#     assert observation.action_succeeded is False
#
#
# def test_on_admin(set_up_state_admin):
#     target_host = set_up_state_admin.state.hosts['Internal']
#
#     k_ip_address = set_up_state_admin.state.hosts['Attacker'].interfaces[0].ip_address
#     pp_ip_address = target_host.interfaces[0].ip_address
#     num_sessions = len(set_up_state_admin.state.sessions['Red'])
#     num_services = len(target_host.services)
#
#     expected_result = {str(num_sessions - 1): {'Interface': [{'IP Address': pp_ip_address}],
#                                                'Processes': [{'Connections': [{'local_address': pp_ip_address,
#                                                                                'local_port': LinuxEphemeralPort(),
#                                                                                'remote_address': k_ip_address,
#                                                                                'remote_port': 4433}],
#                                                               'Known Process': CyEnums.ProcessName.parse_string(
#                                                                   'exploit.exe'),
#                                                               'Process Name': 'exploit.exe',
#                                                               'PID': PID()}],
#                                                'Sessions': [{'Agent': 'Red',
#                                                              'ID': num_sessions,
#                                                              'Type': SessionType.METERPRETER}]},
#                        str(k_ip_address): {'Interface': [{'IP Address': k_ip_address}],
#                                            'Processes': [{'Connections': [{'remote_address': pp_ip_address,
#                                                                            'remote_port': LinuxEphemeralPort(),
#                                                                            'local_address': k_ip_address,
#                                                                            'local_port': 4433}]}],
#
#                                            },
#                        'success': True}
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state_admin.meterpreter_session)
#     observation = action.sim_execute(set_up_state_admin.state)
#     new_service_name = list(target_host.services.keys())[-1]
#
#     assert observation == expected_result
#     assert observation.action_succeeded is True
#     assert len(target_host.services) == num_services + 1
#     assert target_host.services[new_service_name]['active'] is True
#
#
# def test_on_system(set_up_state):
#     # change the session owner to the SYSTEM user
#     admin_user = User(username='SYSTEM', uid=0)
#
#     set_up_state.state.sessions['Red'][set_up_state.meterpreter_session].user = admin_user
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state.meterpreter_session)
#     observation = action.sim_execute(set_up_state.state)
#     assert observation.action_succeeded is True
#
#
# def test_reboot(set_up_state_admin):
#     target_host = set_up_state_admin.state.hosts['Internal']
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state_admin.meterpreter_session)
#     observation = action.sim_execute(set_up_state_admin.state)
#
#     new_process = observation[str(set_up_state_admin.meterpreter_session)]['Processes'][0]
#     new_process_name = new_process['Process Name']
#     new_process_pid = new_process['PID']
#
#     num_sessions = len(set_up_state_admin.state.sessions['Red'])
#
#     action = MeterpreterReboot(session=0, agent='Red', target_session=set_up_state_admin.meterpreter_session)
#     action.sim_execute(set_up_state_admin.state)
#
#     restarted_process = next((process for process in target_host.processes if process.name == new_process_name), None)
#
#     assert restarted_process is not None    # The process has restarted
#     assert restarted_process.pid != new_process_pid  # Restarted process has new PID
#     assert len(set_up_state_admin.state.sessions['Red']) == num_sessions - 2 # lost original meterpreter and ssh gained service meterpreter
#     # invalid test because the original meterpreter session is dead and the new meterpreter session has a different ID
#     # assert set_up_state_admin.state.sessions['Red'][set_up_state_admin.meterpreter_session].process.pid == restarted_process.pid
#
#
# def test_service(set_up_state_admin):
#     target_host = set_up_state_admin.state.hosts['Internal']
#     num_sessions = len(set_up_state_admin.state.sessions['Red'])
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state_admin.meterpreter_session)
#     observation = action.sim_execute(set_up_state_admin.state)
#
#     new_process = observation[str(set_up_state_admin.meterpreter_session)]['Processes'][0]
#     new_process_pid = new_process['PID']
#     new_process_name = new_process['Process Name']
#     new_service_name = list(target_host.services.keys())[-1]
#
#     assert new_process_pid in [process.pid for process in target_host.processes]
#     assert len(set_up_state_admin.state.sessions['Red']) == num_sessions + 1
#
#     set_up_state_admin.state.stop_service(target_host.hostname, new_service_name)
#
#     assert new_process_pid not in [process.pid for process in target_host.processes]
#     assert len(set_up_state_admin.state.sessions['Red']) == num_sessions
#
#     set_up_state_admin.state.start_service(target_host.hostname, new_service_name)
#
#     restarted_process = next((process for process in target_host.processes if process.name == new_process_name), None)
#
#     assert restarted_process is not None
#     assert restarted_process.pid != new_process_pid  # Restarted process has new PID
#     assert len(set_up_state_admin.state.sessions['Red']) == num_sessions + 1  # Gained meterpreter
#
#
# def test_process_kill(set_up_state_admin):
#     target_host = set_up_state_admin.state.hosts['Internal']
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=set_up_state_admin.meterpreter_session)
#     observation = action.sim_execute(set_up_state_admin.state)
#
#     new_process = observation[str(set_up_state_admin.meterpreter_session)]['Processes'][0]
#     new_process_name = new_process['Process Name']
#     new_process_pid = new_process['PID']
#
#     num_sessions = set_up_state_admin.state.sessions['Red']
#
#     set_up_state_admin.state.kill_process(target_host.hostname, new_process['PID'])
#
#     restarted_process = next((process for process in target_host.processes if process.name == new_process_name), None)
#
#     assert restarted_process is not None
#     # assert restarted_process.pid != new_process_pid
#     # NOTE: Is it certain that the new process will have a different pid? No it is not and for the moment we will let them have whatever pid
#
#     assert set_up_state_admin.state.sessions['Red'] == num_sessions
#     # invalid test because the original meterpreter session is dead and the new meterpreter session has a different ID
#     # assert set_up_state_admin.state.sessions['Red'][set_up_state_admin.meterpreter_session].process.pid == restarted_process.pid
