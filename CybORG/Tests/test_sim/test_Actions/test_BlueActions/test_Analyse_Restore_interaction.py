import inspect

import pytest

from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
from CybORG.Simulator.Actions import *
from CybORG.Agents import RedMeanderAgent

SCENARIO = 'Scenario2'
HOSTS = SCENARIOS[SCENARIO]['Hosts']

@pytest.fixture(scope='module')
def cyborg():
    return compromised_cyborg(SCENARIO, stop_host=HOSTS[-1], stop_value=4)

def test_restore_removes_malware(cyborg):
    params = {'session':0, 'agent':'Blue'}
    malware_hosts = []
    for host in HOSTS:
        action = Restore(hostname=host, **params)
        cyborg.step(action=action, agent='Blue')
        action = Analyse(hostname=host, **params)
        results = cyborg.step(action=action, agent='Blue')
        has_files = lambda x: True if x.get('Files') is not None else False
        host_data = [v for k,v in results.observation.items() if k!='success']
        has_malware = any([has_files(v) for v in host_data])
        if has_malware:
            malware_hosts.append((host, results.observation[host]))

    assert len(malware_hosts) == 0

