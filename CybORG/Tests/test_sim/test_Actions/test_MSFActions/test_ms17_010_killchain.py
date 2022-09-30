import inspect
from ipaddress import IPv4Network

from CybORG import CybORG
from CybORG.Shared.Actions import SSHLoginExploit, MeterpreterIPConfig, MSFPingsweep, MSFPortscan, \
    UpgradeToMeterpreter, MSFAutoroute, MS17_010_PSExec
from CybORG.Shared.Enums import OperatingSystemDistribution, OperatingSystemType, \
    Architecture, SessionType, ProcessState, AppProtocol, ProcessType
from CybORG.Tests.EphemeralPort import LinuxEphemeralPort, Win2008EphemeralPort


def test_ms_17_010_nacl_block():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    agent = 'Red'
    initial_result = cyborg.get_observation(agent)
    # create ssh session on pretend pi host
    session = initial_result['Attacker']['Sessions'][0]['ID']
    k_ip_address = initial_result['Attacker']['Interface'][0]['IP Address']
    pp_ip_address = initial_result['Gateway']['Interface'][0]['IP Address']
    action = MSFPortscan(session=session, agent=agent, ip_address=pp_ip_address)
    expected_result = {"success": True,
                       str(pp_ip_address): {
                           'Interface': [{'IP Address': pp_ip_address}],
                           'Processes': [{'Connections': [{
                               'local_address': pp_ip_address,
                               'local_port': 22}]}]},
                       }
    results = cyborg.step(agent, action)

    assert results.observation == expected_result

    action = SSHLoginExploit(session=session, agent=agent, ip_address=pp_ip_address, port=22)
    results = cyborg.step(agent, action)

    target_session = results.observation[str(pp_ip_address)]['Sessions'][0]['ID']
    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)

    target_session = results.observation[str(target_session)]['Sessions'][-1]['ID']
    # use ipconfig on new meterpreter session
    action = MeterpreterIPConfig(session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)

    subnet = results.observation[str(target_session)]['Interface'][0]['Subnet']
    # run ping sweep on new subnet

    action = MSFPingsweep(subnet=subnet, session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)

    hpc_ip_address = None

    for key, value in results.observation.items():
        if key != 'success' and key != 'raw' and key != str(pp_ip_address):
            if 'Interface' not in value:
                continue  # ignoring the *.*.*.1 ip address that is found by scanning the private subnet
            assert len(value['Interface']) == 1
            if 'IP Address' in value['Interface'][0]:
                address = value['Interface'][0]['IP Address']
                hpc_ip_address = address
    assert hpc_ip_address is not None

    expected_result = {'success': False}
    action = MS17_010_PSExec(session=session, agent=agent, ip_address=hpc_ip_address, username='vagrant',
                             password='vagrant')
    results = cyborg.step(agent, action)

    assert results.observation == expected_result


def test_MS17_010_killchain_sim_expected_output():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    agent = 'Red'
    initial_result = cyborg.get_observation(agent)

    # create ssh session on pretend pi host
    session = initial_result['Attacker']['Sessions'][0]['ID']
    k_ip_address = initial_result['Attacker']['Interface'][0]['IP Address']
    pp_ip_address = initial_result['Gateway']['Interface'][0]['IP Address']
    action = MSFPortscan(session=session, agent=agent, ip_address=pp_ip_address)
    expected_result = {"success": True,
                       str(pp_ip_address): {
                           'Interface': [{'IP Address': pp_ip_address}],
                           'Processes': [{'Connections': [{
                               'local_address': pp_ip_address,
                               'local_port': 22}]}]},
                       }
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

    action = SSHLoginExploit(session=session, agent=agent, ip_address=pp_ip_address, port=22)
    expected_result = {"success": True,
                       str(pp_ip_address): {'Interface': [{'IP Address': pp_ip_address}],
                                            'Processes': [{'Connections': [{'Application Protocol': AppProtocol.SSH,
                                                                            'local_address': pp_ip_address,
                                                                            'local_port': 22,
                                                                            'Status': ProcessState.OPEN}],
                                                           'Process Type': ProcessType.SSH},
                                                          {'Connections': [{'local_address': pp_ip_address,
                                                                            'local_port': 22,
                                                                            'remote_address': k_ip_address,
                                                                            'remote_port': LinuxEphemeralPort()}]}],
                                            'Sessions': [{'Agent': 'Red',
                                                          'ID': 1,
                                                          'Type': SessionType.MSF_SHELL,
                                                          'Username': 'pi'}],
                                            'System info': {'Architecture': Architecture.x64,
                                                            'Hostname': 'Gateway',
                                                            'OSDistribution': OperatingSystemDistribution.UBUNTU,
                                                            'OSType': OperatingSystemType.LINUX},
                                            'User Info': [{'Password': 'raspberry',
                                                           'UID': 1001,
                                                           'Username': 'pi'}]
                                            },
                       str(k_ip_address): {
                           'Interface': [{'IP Address': k_ip_address}],
                           'Processes': [{'Connections': [{'remote_address': pp_ip_address,
                                                           'remote_port': 22,
                                                           'local_address': k_ip_address,
                                                           'local_port': LinuxEphemeralPort()}]}]
                       }}
    results = cyborg.step(agent, action)
    assert results.reward == 0
    assert not results.done

    assert results.observation == expected_result

    target_session = results.observation[str(pp_ip_address)]['Sessions'][0]['ID']
    # upgrade to meterpreter
    expected_result = {'1': {'Interface': [{'IP Address': pp_ip_address}],
                             'Processes': [{'Connections': [{'local_address': pp_ip_address,
                                                             'local_port': LinuxEphemeralPort(),
                                                             'remote_address': k_ip_address,
                                                             'remote_port': 4433}]}],
                             'Sessions': [{'Agent': 'Red',
                                           'ID': 2,
                                           'Type': SessionType.METERPRETER}]},
                       str(k_ip_address): {'Interface': [{'IP Address': k_ip_address}],
                                           'Processes': [{'Connections': [{'remote_address': pp_ip_address,
                                                                           'remote_port': LinuxEphemeralPort(),
                                                                           'local_address': k_ip_address,
                                                                           'local_port': 4433}]}],

                                           },
                       'success': True}
    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

    target_session = results.observation[str(target_session)]['Sessions'][-1]['ID']
    # use ipconfig on new meterpreter session
    expected_result = {'success': True,
                       str(target_session): {'Interface': [{'IP Address': pp_ip_address,
                                                            'Interface Name': 'eth0',
                                                            'Subnet': IPv4Network(f'{str(pp_ip_address)}/28', False)}
                                                           ]}
                       }
    action = MeterpreterIPConfig(session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

    subnet = results.observation[str(target_session)]['Interface'][0]['Subnet']
    # run ping sweep on new subnet

    action = MSFPingsweep(subnet=subnet, session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    hpc_ip_address = None

    for key, value in results.observation.items():
        if key != 'success' and key != 'raw' and key != str(pp_ip_address):
            if 'Interface' not in value:
                continue  # ignoring the *.*.*.1 ip address that is found by scanning the private subnet
            assert len(value['Interface']) == 1
            if 'IP Address' in value['Interface'][0]:
                address = value['Interface'][0]['IP Address']
                hpc_ip_address = address
    assert hpc_ip_address is not None
    expected_result = {'success': True,
                       str(pp_ip_address): {'Interface': [{'IP Address': pp_ip_address,
                                                           'Subnet': subnet}]},
                       str(hpc_ip_address): {'Interface': [{'IP Address': hpc_ip_address,
                                                            'Subnet': subnet}]}}
    assert results.observation == expected_result

    expected_result = {'success': True,
                       str(hpc_ip_address): {'Interface': [{'IP Address': hpc_ip_address}],
                                             'Processes': [{'Connections': [{'local_address': hpc_ip_address,
                                                                             'local_port': 22}]},
                                                            {'Connections': [{'local_address': hpc_ip_address,
                                                                              'local_port': 80}]}
                                                            ]}}
    action = MSFPortscan(agent=agent, ip_address=hpc_ip_address, session=session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

    action = SSHLoginExploit(session=session, agent=agent, ip_address=hpc_ip_address, port=22)
    results = cyborg.step(agent, action)
    assert not results.done

    expected_result = {'success': True,
                       str(hpc_ip_address): {'User Info': [{'Username': 'vagrant', 'Password': 'vagrant'}],
                                             'Processes': [
                                                 {'Connections': [
                                                     {'local_port': 22, 'local_address': hpc_ip_address,
                                                      'Application Protocol': AppProtocol.SSH,
                                                      'Status': ProcessState.OPEN}],
                                                     'Process Type': ProcessType.SSH},
                                                 {'Connections': [
                                                     {'local_port': 22, 'remote_port': Win2008EphemeralPort(),
                                                      'local_address': hpc_ip_address,
                                                      'remote_address': k_ip_address}]}],
                                             'Interface': [{'IP Address': hpc_ip_address}],
                                             'Sessions': [
                                                 {'Username': 'vagrant', 'ID': 3, 'Type': SessionType.MSF_SHELL,
                                                  'Agent': 'Red'}]},
                       str(k_ip_address): {
                           'Interface': [{'IP Address': k_ip_address}],
                           'Processes': [{'Connections': [{'remote_address': hpc_ip_address,
                                                           'remote_port': 22,
                                                           'local_address': k_ip_address,
                                                           'local_port': LinuxEphemeralPort()}]}]
                       }}

    assert results.observation == expected_result
    assert results.reward == 0

    # use autoroute on new meterpreter session
    expected_result = {'success': True,
                       str(target_session): {'Interface': [{'Subnet': subnet}]}}
    action = MSFAutoroute(session=session, agent=agent, target_session=target_session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0

    assert results.observation == expected_result

    expected_result = {'success': True,
                       str(hpc_ip_address): {'Interface': [{'IP Address': hpc_ip_address}],
                                             'Processes': sorted([{'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 445}]},
                                                                  {'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 443}]},
                                                                  {'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 135}]},
                                                                  {'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 139}]},
                                                                  {'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 80}]},
                                                                  {'Connections': [{'local_address': hpc_ip_address,
                                                                                    'local_port': 22}]}],
                                                                 key=lambda i: i['Connections'][0]['local_port'])}
                       }
    action = MSFPortscan(agent=agent, ip_address=hpc_ip_address, session=session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0

    results.observation[str(hpc_ip_address)]['Processes'] = sorted(
        results.observation[str(hpc_ip_address)]['Processes'], key=lambda i: i['Connections'][0]['local_port'])
    assert results.observation == expected_result

    action = SSHLoginExploit(session=session, agent=agent, ip_address=hpc_ip_address, port=22)
    results = cyborg.step(agent, action)
    expected_result = {'success': True,
                       str(hpc_ip_address): {'User Info': [{'Username': 'vagrant', 'Password': 'vagrant'}],
                                             'Processes': [
                                                 {'Connections': [
                                                     {'local_port': 22,
                                                      'local_address': hpc_ip_address,
                                                      'Application Protocol': AppProtocol.SSH,
                                                      'Status': ProcessState.OPEN}],
                                                     'Process Type': ProcessType.SSH},
                                                 {'Connections': [
                                                     {'local_port': 22,
                                                      'local_address': hpc_ip_address,
                                                      'remote_address': pp_ip_address}]}],
                                             'Interface': [{'IP Address': hpc_ip_address}],
                                             'Sessions': [
                                                 {'Username': 'vagrant', 'ID': 4, 'Type': SessionType.MSF_SHELL,
                                                  'Agent': 'Red'}]},
                       str(pp_ip_address): {'Interface': [{'IP Address': pp_ip_address}],
                                            'Processes': [{'Connections': [{'local_address': pp_ip_address,
                                                                            'remote_address': hpc_ip_address,
                                                                            'remote_port': 22}]}
                                                          ]}
                       }
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

    action = MS17_010_PSExec(session=session, agent=agent, ip_address=hpc_ip_address, username='vagrant',
                             password='vagrant')
    attempts = 0
    MAX_ATTEMPTS = 5
    while attempts < MAX_ATTEMPTS:
        results = cyborg.step(agent, action)
        # pprint(results.observation)
        if results.observation['success'] == True:
            break
        attempts += 1
    expected_result = {str(hpc_ip_address): {'Interface': [{'IP Address': hpc_ip_address}],
                                             'Processes': [{'Connections': [
                                                 {'local_address': hpc_ip_address,
                                                  'local_port': 139,
                                                  'Status': ProcessState.OPEN}],
                                                 'Process Type': ProcessType.SMB},
                                                 {'Connections': [{'local_address': hpc_ip_address,
                                                                   'local_port': 44444,
                                                                   'remote_address': pp_ip_address}]}
                                             ],
                                             'Sessions': [{'Agent': 'Red',
                                                           'ID': 5,
                                                           'Type': SessionType.METERPRETER}]},
                       'success': True}
    assert results.observation == expected_result
    assert not results.done
    assert results.reward == 10


# def test_with_reboot():
#     path = str(inspect.getfile(CybORG))
#     path = path[:-10] + '/Shared/Scenarios/Scenario1_WindowsPersistence.yaml'
#     cyborg = CybORG(path, 'sim')
#     agent = 'Red'
#     initial_result = cyborg.get_observation(agent)
#     target_hostname = 'Internal'
#     target_address = initial_result[target_hostname]['Interface'][0]['IP Address']
#
#     action = MSFPortscan(ip_address=target_address, session=0, agent=agent)
#     cyborg.step(agent, action)
#
#     action = SSHLoginExploit(ip_address=target_address, agent=agent, session=0, port=22)
#     cyborg.step(agent, action)
#
#     action = UpgradeToMeterpreter(session=0, agent=agent, target_session=1)
#     cyborg.step(agent, action)
#
#     action = MSFAutoroute(session=0, agent=agent, target_session=2)
#     cyborg.step(agent, action)
#
#     state = cyborg.environment_controller.state
#     state.reboot_host(target_hostname)
#
#     action = MS17_010_PSExec(ip_address=target_address, session=0, agent=agent, username='vagrant', password='vagrant')
#     observation = cyborg.step(agent, action).observation
#
#     assert observation.action_succeeded is False
