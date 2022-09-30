import inspect

import pytest

from CybORG import CybORG
from CybORG.Simulator.Actions.MSFActionsFolder import GetUid
from CybORG.Shared.Enums import BuiltInGroups
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


@pytest.mark.parametrize(["host", "user", "session_type", "expected_observation"],
                         [("Attacker", "root", "msf shell", {
                             "success": False
                         }), ("Gateway", "root", "msf shell", {
                             "success": False
                         }), ("Gateway", "pi", "msf shell", {
                             "success": False
                         }), ("Gateway", "pi", "meterpreter", {
                             "success": True,
                             "1": {
                                 "User Info": [
                                     {
                                         'Username': 'pi',
                                     }
                                 ]
                             }
                         }), ("Gateway", "root", "meterpreter", {
                             "success": True,
                             "1": {
                                 "User Info": [
                                     {
                                         "Username": "root"
                                     }
                                 ]
                             }
                         }), ("Gateway", "ubuntu", "meterpreter", {
                             "success": True,
                             "1": {
                                 "User Info": [
                                     {"Username": "ubuntu"}
                                 ]
                             }
                         }), ("Internal", "SYSTEM", "msf shell", {
                             "success": False
                         }), ("Internal", "SYSTEM", "meterpreter", {
                             "success": True,
                             "1": {
                                 "User Info": [
                                     {"Username": "SYSTEM"}
                                 ]
                             }
                         })])
def test_execute(cyborg_scenario1_state, host, user, session_type, expected_observation):
    state = cyborg_scenario1_state
    parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)

    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.execute(state)

    assert observation.get_dict() == expected_observation


def test_execute_inactive(cyborg_scenario1_state):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    state = cyborg_scenario1_state

    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)

    session.active = False
    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.execute(state)
    assert observation.get_dict() == expected_observation


def test_execute_dead(cyborg_scenario1_state):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    state = cyborg_scenario1_state

    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)

    state.remove_process(session.hostname, session.pid)
    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.execute(state)
    assert observation.get_dict() == expected_observation
