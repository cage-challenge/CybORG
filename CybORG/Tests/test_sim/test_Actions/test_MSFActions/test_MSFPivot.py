import inspect
from ipaddress import IPv4Address

import pytest

from CybORG import CybORG

from CybORG.Shared.Enums import BuiltInGroups
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.Actions import MSFAutoroute, KillProcessLinux, MSFEternalBlue, MS17_010_PSExec


def test_pivot_execute(cyborg_scenario1_state):
    state = cyborg_scenario1_state
    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', session_type="meterpreter", parent=msf_session.ident)
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    observation = action.execute(state)
    assert type(observation) is Observation


def test_kill_pivot_execute(cyborg_scenario1_state):
    state = cyborg_scenario1_state
    internal_ip_address = [ip_address for ip_address, host in state.ip_addresses.items() if host == 'Internal'][0]
    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', session_type="meterpreter", parent=msf_session.ident)
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    action.execute(state)
    action = MS17_010_PSExec(internal_ip_address, msf_session.ident, 'Red', username='vagrant', password='vagrant')
    observation = action.execute(state)
    assert observation.get_dict()['success'] == True
    kill_action = KillProcessLinux(session=session.ident, agent='Red', process=session.pid)
    kill_action.execute(state)
    observation = action.execute(state)
    assert observation.get_dict()['success'] == False



def test_execute_inactive_server(cyborg_scenario1_state):
    expected_observation = {"success": False}
    state = cyborg_scenario1_state

    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', parent=msf_session.ident)

    msf_session.active = False
    action = MSFAutoroute(session=msf_session.ident, target_session=session.ident, agent='Red')
    observation = action.execute(state)
    assert observation.get_dict() == expected_observation


def test_execute_dead_server(cyborg_scenario1_state):
    expected_observation = {"success": False}
    state = cyborg_scenario1_state

    msf_session = state.sessions['Red'][0]
    session = state.add_session(host='Gateway', user='root', agent='Red', parent=msf_session.ident)

    state.remove_process(msf_session.hostname, msf_session.pid)
    action = MSFAutoroute(session=session.ident, agent='Red', target_session=msf_session)
    observation = action.execute(state)
    assert observation.get_dict() == expected_observation
