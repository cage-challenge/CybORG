import inspect

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions import *
from CybORG.Agents import RedMeanderAgent


hosts = [
        'User0',
        'User1',
        'User2',
        'User3',
        'User4',
        'Enterprise0',
        'Enterprise1',
        'Enterprise2',
        'Defender',
        'Op_Server0',
        'Op_Host0',
        'Op_Host1',
        'Op_Host2',
        ]

@pytest.fixture
def cyborg():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
    return CybORG(path, 'sim', agents={'Red':RedMeanderAgent})

def test_restore_removes_malware(cyborg):
    history = []
    for i in range(50):
        cyborg.step()
        act = cyborg.get_last_action('Red')
        history.append(act)
        if act.__class__.__name__ == 'Impact':
            break

    params = {'session':0, 'agent':'Blue'}
    malware_hosts = []
    for host in hosts:
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

