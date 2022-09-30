import inspect

from CybORG import CybORG
from CybORG.Shared.Actions import MSFPortscan, SSHLoginExploit, MSFPingsweep, MeterpreterIPConfig, UpgradeToMeterpreter


def test_MSFPortscan():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    agent = 'Red'
    initial_result = cyborg.get_observation(agent)
    # create ssh session on pretend pi host
    session = initial_result['Attacker']['Sessions'][0]['ID']
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


def test_MSFPortscan_NACL_block():
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

    expected_result = {'success': True,
                       str(hpc_ip_address): {'Interface': [{'IP Address': hpc_ip_address}],
                                             'Processes': [{'Connections': [{'local_address': hpc_ip_address,
                                                                             'local_port': 22}]},
                                                           {'Connections': [{'local_address': hpc_ip_address,
                                                                             'local_port': 80}]}
                                                           ]}}
    action = MSFPortscan(agent=agent, ip_address=hpc_ip_address, session=session)
    results = cyborg.step(agent, action)

    assert results.observation == expected_result
