import inspect
from ipaddress import IPv4Network, IPv4Address
from pprint import pprint

from CybORG import CybORG
from CybORG.Shared.Actions import SSHLoginExploit, MeterpreterIPConfig, MSFPingsweep, MSFPortscan, UpgradeToMeterpreter, \
    MSFAutoroute, MS17_010_PSExec
from CybORG.Shared.Enums import OperatingSystemDistribution, OperatingSystemKernelVersion, OperatingSystemType, \
    Architecture, SessionType, ProcessState, AppProtocol, ProcessType
from CybORG.Tests.EphemeralPort import LinuxEphemeralPort, Win2008EphemeralPort

def test_pingsweep():
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
    results = cyborg.step(agent, action)


    ssh_session = results.observation[str(pp_ip_address)]['Sessions'][0]['ID']
    # upgrade to meterpreter
    action = UpgradeToMeterpreter(session=session, agent=agent, target_session=ssh_session)
    results = cyborg.step(agent, action)
    met_session = results.observation[str(ssh_session)]['Sessions'][-1]['ID']

    # use ipconfig on new meterpreter session
    action = MeterpreterIPConfig(session=session, agent=agent, target_session=met_session)
    results = cyborg.step(agent, action)

    subnet = results.observation[str(met_session)]['Interface'][0]['Subnet']
    # run ping sweep on new subnet

    action = MSFPingsweep(subnet=subnet, session=session, agent=agent, target_session=met_session)
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

    action = MSFPingsweep(subnet=subnet, session=session, agent=agent, target_session=ssh_session)
    results = cyborg.step(agent, action)
    assert not results.done
    assert results.reward == 0
    assert results.observation == expected_result
