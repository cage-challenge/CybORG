import inspect
from ipaddress import IPv4Address

import pytest

from CybORG import CybORG

from CybORG.Shared.Enums import BuiltInGroups
from CybORG.Shared.Observation import Observation
from CybORG.Shared.Actions import MSFAutoroute, KillProcessLinux, MSFEternalBlue, MS17_010_PSExec


@pytest.fixture()
def set_up_state():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    state = cyborg.environment_controller.state
    return state


def test_pivot_sim_execute(set_up_state):
    state = set_up_state
    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', session_type="meterpreter", parent=msf_session)
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    observation = action.sim_execute(state)
    assert type(observation) is Observation


def test_kill_pivot_sim_execute(set_up_state):
    state = set_up_state
    internal_ip_address = [ip_address for ip_address, host in state.ip_addresses.items() if host == 'Internal'][0]
    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', session_type="meterpreter", parent=msf_session)
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    action.sim_execute(state)
    action = MS17_010_PSExec(internal_ip_address, msf_session.ident, 'Red', username='vagrant', password='vagrant')
    observation = action.sim_execute(state)
    assert observation.get_dict()['success'] == True
    kill_action = KillProcessLinux(session=session.ident, agent='Red', process=session.pid)
    kill_action.sim_execute(state)
    observation = action.sim_execute(state)
    assert observation.get_dict()['success'] == False



def test_sim_execute_inactive_server(set_up_state):
    expected_observation = {"success": False}
    state = set_up_state

    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', parent=msf_session)

    msf_session.active = False
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    observation = action.sim_execute(state)
    assert observation.get_dict() == expected_observation


def test_sim_execute_dead_server(set_up_state):
    expected_observation = {"success": False}
    state = set_up_state

    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', parent=msf_session)

    state.remove_process(msf_session.host, msf_session.pid)
    action = MSFAutoroute(session=session.ident, agent='Red', target_session=msf_session)
    observation = action.sim_execute(state)
    assert observation.get_dict() == expected_observation
