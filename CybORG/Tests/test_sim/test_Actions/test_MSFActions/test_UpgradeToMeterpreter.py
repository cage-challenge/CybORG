import inspect
from ipaddress import IPv4Address

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions import UpgradeToMeterpreter, SSHLoginExploit, MSFPortscan, MSFAutoroute, MSFPingsweep
from CybORG.Shared.Enums import SessionType, AppProtocol
from CybORG.Tests.EphemeralPort import LinuxEphemeralPort


def test_upgrade_msf_shell():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')

    agent = 'Red'
    initial_result = cyborg.get_observation(agent)
    # create ssh session on pretend pi host
    session = initial_result['Attacker']['Sessions'][0]['ID']
    k_ip_address = initial_result['Attacker']['Interface'][0]['IP Address']
    pp_ip_address = initial_result['Gateway']['Interface'][0]['IP Address']

    action = SSHLoginExploit(session=session, agent=agent, ip_address=pp_ip_address, port=22)
    results = cyborg.step(agent, action, skip_valid_action_check=True)

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

    expected_result = {'2': {'Interface': [{'IP Address': pp_ip_address}],
                             'Processes': [{'Connections': [{'local_address': pp_ip_address,
                                                             'local_port': LinuxEphemeralPort(),
                                                             'remote_address': k_ip_address,
                                                             'remote_port': 4433}]}],
                             'Sessions': [{'Agent': 'Red',
                                           'ID': 3,
                                           'Type': SessionType.METERPRETER}]},
                       str(k_ip_address): {'Interface': [{'IP Address': k_ip_address}],
                                           'Processes': [{'Connections': [{'remote_address': pp_ip_address,
                                                                           'remote_port': LinuxEphemeralPort(),
                                                                           'local_address': k_ip_address,
                                                                           'local_port': 4433}]}],

                                           },
                       'success': True}
    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=2)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result

def test_interesting_sim_behaviour():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')

    agent = 'Red'
    initial_result = cyborg.get_observation(agent)
    # create ssh session on pretend pi host
    session = initial_result['Attacker']['Sessions'][0]['ID']
    k_ip_address = initial_result['Attacker']['Interface'][0]['IP Address']
    k_subnet = initial_result['Attacker']['Interface'][0]['Subnet']
    g_ip_address = initial_result['Gateway']['Interface'][0]['IP Address']
    g_subnet= initial_result['Gateway']['Interface'][0]['Subnet']


    action = MSFPortscan(agent=agent, ip_address=g_ip_address, session=session)
    results = cyborg.step(agent, action)

    action = SSHLoginExploit(session=session, agent=agent, ip_address=g_ip_address, port=22)
    results = cyborg.step(agent, action)

    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=1)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0

    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=2)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0

    action = MSFAutoroute(session=session, agent=agent, target_session=3)
    results = cyborg.step(agent, action)

    action = MSFPingsweep(session=session, agent=agent, target_session=3, subnet=k_subnet)
    results = cyborg.step(agent, action)

    action = MSFPortscan(agent=agent, ip_address=g_ip_address, session=session)
    results = cyborg.step(agent, action)

    action = MSFAutoroute(session=session, agent=agent, target_session=2)
    results = cyborg.step(agent, action)

    action = SSHLoginExploit(session=session, agent=agent, ip_address=g_ip_address, port=22)
    results = cyborg.step(agent, action)

    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=2)
    results = cyborg.step(agent, action)
