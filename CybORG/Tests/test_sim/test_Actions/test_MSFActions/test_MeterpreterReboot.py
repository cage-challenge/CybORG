import inspect

import pytest

from CybORG import CybORG
from CybORG.Simulator.Actions import MeterpreterReboot, GetUid


@pytest.mark.parametrize(["host", "user", "session_type", "expected_observation", "expected_observation_after"],
                         [("Attacker", "root", "msf shell", {"success": False}, {
                             "success": False
                         }), ("Gateway", "root", "msf shell", {"success": False}, {
                             "success": False
                         }), ("Gateway", "pi", "msf shell", {"success": False}, {
                             "success": False
                         }), ("Gateway", "pi", "meterpreter", {"success": True}, {
                             "success": False
                         }), ("Gateway", "root", "meterpreter", {"success": True}, {
                             "success": False
                         }), ("Gateway", "ubuntu", "meterpreter", {"success": True}, {
                             "success": False
                         }), ("Internal", "SYSTEM", "msf shell", {"success": False}, {
                             "success": False
                         }), ("Internal", "SYSTEM", "meterpreter", {"success": True}, {
                             "success": False
                         })])
def test_execute(cyborg_scenario1, host, user, session_type, expected_observation, expected_observation_after):
    cyborg = cyborg_scenario1
    state = cyborg.environment_controller.state
    parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)
    action = MeterpreterReboot(session=parent.ident, target_session=session.ident, agent="Red")
    observation = cyborg.step(agent='Red', action=action, skip_valid_action_check=True).observation
    assert observation == expected_observation

    action = GetUid(session=parent.ident, target_session=session.ident, agent="Red")

    observation = action.execute(state).data

    if (user == "root" or user == "user" or user == "SYSTEM") and session_type == "meterpreter":
        observation3 = cyborg.get_agent_state('True')
        if host == "Gateway":
            assert len(observation3[host]["Processes"]) == 1
        elif host == "Internal":
            assert len(observation3[host]["Processes"]) == 5
    assert observation== expected_observation_after


def test_execute_inactive(cyborg_scenario1):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    cyborg = cyborg_scenario1
    state = cyborg.environment_controller.state

    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)
    session2 = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)
    file = state.add_file(host=host, name="file", path="/tmp/", user=user)
    tmp_file = state.add_file(host=host, name="file2", path="/tmp/", user=user)

    session.active = False
    action = MeterpreterReboot(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.execute(state).data
    assert observation== expected_observation


def test_execute_dead(cyborg_scenario1):
    expected_observation = {"success": False}
    host = "Gateway"
    user = "root"
    session_type = "meterpreter"
    cyborg = cyborg_scenario1
    state = cyborg.environment_controller.state
    parent = None
    if session_type != 'shell':
        parent = state.sessions['Red'][0]
    session = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)
    session2 = state.add_session(host=host, agent="Red", user=user, session_type=session_type, parent=parent.ident)
    file = state.add_file(host=host, name="file", path="/some/random/path", user=user)
    tmp_file = state.add_file(host=host, name="file2", path='/tmp/', user=user)

    state.remove_process(session.hostname, session.pid)
    action = MeterpreterReboot(session=parent.ident, target_session=session.ident, agent="Red")
    observation = action.execute(state).data
    assert observation== expected_observation
