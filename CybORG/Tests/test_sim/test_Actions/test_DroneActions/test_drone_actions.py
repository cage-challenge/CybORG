import pytest

from CybORG import CybORG
from CybORG.Simulator.Actions import Remove, Sleep
from CybORG.Simulator.Actions.ConcreteActions.EscalateActions.SeizeControl import SeizeControl
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitDroneVulnerability import ExploitDroneVulnerability
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator

"""Testing ExploitDroneVulnerability"""


def test_red_exploit_on_unattacked_blue(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert results.observation['success'] == True
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation
    # check that created session still exists in observation in the next step
    results = cyborg.step(agent=red_agent, action=Sleep())
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation


def test_red_exploit_on_attacked_blue(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert results.observation['success'] == True
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation
    # check that created session still exists in observation in the next step
    results = cyborg.step(agent=red_agent, action=Sleep())
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation


def test_red_exploit_on_unattacked_red(unattacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_red
    assert cyborg.environment_controller.state.sessions[red_agent][0].username == 'root'
    assert cyborg.environment_controller.state.sessions['red_agent_' + target_agent.split('_')[-1]][
               0].username == 'root'
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert cyborg.environment_controller.state.sessions[red_agent][0].username == 'root'
    assert cyborg.environment_controller.state.sessions['red_agent_' + target_agent.split('_')[-1]][
               0].username == 'root'
    assert results.observation['success'] == True
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation
    results = cyborg.step(agent=red_agent, action=Sleep())
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation


def test_red_exploit_on_attacked_red(attacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_red
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert results.observation['success'] == True
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation
    results = cyborg.step(agent=red_agent, action=Sleep())
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation


"""Testing SeizeControl"""


def test_red_seize_on_unattacked_blue(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    action = SeizeControl(agent=red_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=red_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       red_agent]) == action
    assert results.observation['success'] == False, cyborg.environment_controller.observation[red_agent].raw
    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)


def test_red_seize_on_attacked_blue(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    action = SeizeControl(agent=red_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=red_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       red_agent]) == action
    assert results.observation['success'] == True, cyborg.environment_controller.observation[red_agent].raw
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"


def test_red_seize_on_unattacked_red(unattacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_red
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    action = SeizeControl(agent=red_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=red_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       red_agent]) == action
    assert results.observation['success'] == False, cyborg.environment_controller.observation[red_agent].raw
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"


def test_red_seize_on_attacked_red(attacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_red
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    action = SeizeControl(agent=red_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=red_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       red_agent]) == action
    assert results.observation['success'] == True, cyborg.environment_controller.observation[red_agent].raw
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"


"""Testing Remove"""


def test_blue_remove_on_unattacked_blue(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=target_agent, action=RemoveOtherSessions(agent=target_agent, session=0))
    assert results.observation['success'] == False
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)


def test_blue_remove_on_attacked_blue(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=target_agent, action=RemoveOtherSessions(agent=target_agent, session=0))
    assert results.observation['success'] == True
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)


"""Testing Retake Control"""


def test_blue_retake_on_unattacked_blue(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    assert target_agent in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    action = RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=blue_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       blue_agent]) == action
    assert results.observation['success'] == False
    assert target_agent in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space(target_agent)['session']) > 0


def test_blue_retake_on_attacked_blue(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent in cyborg.active_agents
    action = RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=blue_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       blue_agent]) == action
    assert results.observation['success'] == False
    assert target_agent in cyborg.active_agents
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space(target_agent)['session']) > 0


def test_blue_retake_on_unattacked_red(unattacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_red
    assert target_agent not in cyborg.active_agents
    action = RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=blue_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       blue_agent]) == action
    assert results.observation['success'] == True
    assert target_agent in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space(target_agent)['session']) > 0


def test_blue_retake_on_attacked_red(attacked_red):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_red
    assert 'Sessions' in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert target_agent not in cyborg.active_agents
    action = RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)
    results = cyborg.step(agent=blue_agent, action=action)
    assert cyborg.environment_controller.replace_action_if_invalid(action,
                                                                   cyborg.environment_controller.agent_interfaces[
                                                                       blue_agent]) == action
    assert results.observation['success'] == True
    assert target_agent in cyborg.active_agents
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    assert len(cyborg.get_action_space(target_agent)['session']) > 0


def test_remove_always():
    sg = DroneSwarmScenarioGenerator(max_length_data_links=28, num_drones=15, red_spawn_rate=0, starting_num_red=1)
    cyborg = CybORG(sg, 'sim')
    for i in range(500):
        # cyborg.render()
        actions = {}
        agent_list = ['drone_0', 'drone_1', 'drone_2', 'drone_3', 'drone_4', 'drone_5', 'drone_6', 'drone_7', 'drone_8',
                      'drone_9', 'drone_10', 'drone_11', 'drone_12', 'drone_13', 'drone_14']

        for agent in cyborg.active_agents:
            if 'blue' in agent:
                actions[agent] = RemoveOtherSessions(agent=agent, session=0)
                # actions[agent] = RetakeControl(agent=agent, session=0, ip_address=cyborg.get_ip_map()[random.choice(agent_list)])

        # breakpoint()
        cyborg.parallel_step(actions)


def test_restore_always():
    sg = DroneSwarmScenarioGenerator(max_length_data_links=28, num_drones=15, red_spawn_rate=0, starting_num_red=1)
    cyborg = CybORG(sg, 'sim')
    for i in range(500):
        # cyborg.render()
        actions = {}
        agent_list = ['drone_0', 'drone_1', 'drone_2', 'drone_3', 'drone_4', 'drone_5', 'drone_6', 'drone_7', 'drone_8',
                      'drone_9', 'drone_10', 'drone_11', 'drone_12', 'drone_13', 'drone_14']

        for agent in cyborg.active_agents:
            if 'blue' in agent:
                actions[agent] = RetakeControl(agent=agent, session=0,
                                               ip_address=cyborg.get_ip_map()[cyborg.np_random.choice(agent_list)])

        # breakpoint()
        cyborg.parallel_step(actions)
