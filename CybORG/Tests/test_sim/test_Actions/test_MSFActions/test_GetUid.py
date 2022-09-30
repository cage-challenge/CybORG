import inspect

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions.MSFActionsFolder import GetUid
from CybORG.Shared.Enums import BuiltInGroups


@pytest.fixture()
def set_up_state():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    state = cyborg.environment_controller.state
    return state


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
def test_sim_execute(set_up_state, host, user, session_type, expected_observation):
    state = set_up_state
    parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent)

    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.sim_execute(state)

    assert observation.get_dict() == expected_observation


def test_sim_execute_inactive(set_up_state):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    state = set_up_state

    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent)

    session.active = False
    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.sim_execute(state)
    assert observation.get_dict() == expected_observation


def test_sim_execute_dead(set_up_state):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    state = set_up_state

    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent)

    state.remove_process(session.host, session.pid)
    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.sim_execute(state)
    assert observation.get_dict() == expected_observation
