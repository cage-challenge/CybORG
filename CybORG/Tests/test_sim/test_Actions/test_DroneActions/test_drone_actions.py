from pprint import pprint

import numpy as np
import pytest

from CybORG import CybORG
from CybORG.Agents import SleepAgent, DroneRedAgent
from CybORG.Simulator.Actions import Remove, Sleep
from CybORG.Simulator.Actions.ConcreteActions.ActivateTrojan import ActivateTrojan
from CybORG.Simulator.Actions.ConcreteActions.EscalateActions.SeizeControl import SeizeControl
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitDroneVulnerability import ExploitDroneVulnerability
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
from CybORG.Tests.utils import AlwaysTrueGenerator

"""Testing ExploitDroneVulnerability"""

def test_red_exploit_indirect():
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=1, max_length_data_links=7, starting_positions=np.array([np.array([5, 5]),np.array([5, 10]),np.array([5, 15])]), agent_to_drone_mapping={0: 'red', 1:'blue', 2:'blue'}, default_red_agent=SleepAgent, red_internal_only=False)
    cyborg = CybORG(scenario_generator=sg, seed=AlwaysTrueGenerator())
    red_agent = 'red_agent_0'
    assert red_agent in cyborg.active_agents
    blue_agent = 'blue_agent_1'
    assert blue_agent in cyborg.active_agents
    target_agent = 'blue_agent_2'
    assert target_agent in cyborg.active_agents

    target_obs = cyborg.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']
    assert 'Sessions' not in cyborg.get_observation(red_agent).get(target_host, {}), cyborg.get_observation(red_agent)
    results = cyborg.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert results.observation['success'] == True
    assert 'Sessions' in results.observation.get(target_host, {}), results.observation
    # check that blue agent detected attack
    blue_obs = cyborg.get_observation(blue_agent)
    assert blue_obs['drone_1']['Interface'][0]['NetworkConnections'][0]['local_address'] == target_ip

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

def test_activate_trojan():
    sg = DroneSwarmScenarioGenerator(num_drones=3, max_length_data_links=300, starting_num_red=0, red_internal_only=False)
    cyborg = CybORG(scenario_generator=sg, environment='sim')
    cyborg.reset()
    assert len([i for i in cyborg.active_agents if 'blue' in i]) == 3
    agent = 'Red_Trojan'
    action = ActivateTrojan(agent, 'drone_0')
    cyborg.step(agent, action)
    assert len([i for i in cyborg.active_agents if 'blue' in i]) == 2
    assert 'red_agent_0' in cyborg.active_agents
    action = ActivateTrojan(agent, 'drone_1')
    cyborg.step(agent, action)
    assert len([i for i in cyborg.active_agents if 'blue' in i]) == 1
    assert 'red_agent_1' in cyborg.active_agents
    action = ActivateTrojan(agent, 'drone_2')
    cyborg.step(agent, action)
    assert len([i for i in cyborg.active_agents if 'blue' in i]) == 0
    assert 'red_agent_2' in cyborg.active_agents


def test_inconsistent_sessions():
    sg = DroneSwarmScenarioGenerator(num_drones=3, max_length_data_links=300)
    cyborg = CybORG(scenario_generator=sg, environment='sim', seed=AlwaysTrueGenerator())

    ip_map = cyborg.get_ip_map()

    state = cyborg.environment_controller.state

    actions = [
        ActivateTrojan('Red_Trojan', 'drone_0'),
        ActivateTrojan('Red_Trojan', 'drone_1'),
        ExploitDroneVulnerability(0, 'red_agent_1', ip_map['drone_0']),
        SeizeControl(ip_map['drone_0'], 0, 'red_agent_1'),
        # RetakeControl(0, 'blue_agent_2', ip_map['drone_0'])
    ]

    for a in actions:
        a.execute(state)

    host_sessions = {hostname: host.sessions for hostname, host in cyborg.environment_controller.state.hosts.items()}
    for sess in host_sessions.values():
        for s in sess.values():
            for k in s:
                assert len([i for i in s if i==k]) == 1
    for hostname, host in cyborg.environment_controller.state.hosts.items():
        for agent in cyborg.environment_controller.agent_interfaces.keys():
            temp = [k for k, v in cyborg.environment_controller.state.sessions[agent].items() if v.hostname == hostname]
            assert temp == host.sessions[agent]
    a = RetakeControl(0, 'blue_agent_2', ip_map['drone_0'])
    a.execute(state)

    host_sessions = {hostname: host.sessions for hostname, host in cyborg.environment_controller.state.hosts.items()}
    assert len(host_sessions['drone_0']['red_agent_0']) == 0


def test_inconsistent_sessions_own_host():
    sg = DroneSwarmScenarioGenerator(num_drones=3, max_length_data_links=300)
    cyborg = CybORG(scenario_generator=sg, environment='sim', seed=AlwaysTrueGenerator())

    ip_map = cyborg.get_ip_map()

    state = cyborg.environment_controller.state

    actions = [
        ActivateTrojan('Red_Trojan', 'drone_0'),
        ActivateTrojan('Red_Trojan', 'drone_1'),
        ExploitDroneVulnerability(0, 'red_agent_0', ip_map['drone_0']),
        ExploitDroneVulnerability(0, 'red_agent_1', ip_map['drone_0']),
        SeizeControl(ip_map['drone_0'], 0, 'red_agent_1'),
        # RetakeControl(0, 'blue_agent_2', ip_map['drone_0'])
    ]

    for a in actions:
        a.execute(state)

    host_sessions = {hostname: host.sessions for hostname, host in cyborg.environment_controller.state.hosts.items()}
    for sess in host_sessions.values():
        for s in sess.values():
            for k in s:
                assert len([i for i in s if i==k]) == 1
    for hostname, host in cyborg.environment_controller.state.hosts.items():
        for agent in cyborg.environment_controller.agent_interfaces.keys():
            temp = [k for k, v in cyborg.environment_controller.state.sessions[agent].items() if v.hostname == hostname]
            assert temp == host.sessions[agent]
    a = RetakeControl(0, 'blue_agent_2', ip_map['drone_0'])
    a.execute(state)

    host_sessions = {hostname: host.sessions for hostname, host in cyborg.environment_controller.state.hosts.items()}
    assert len(host_sessions['drone_0']['red_agent_0']) == 0


def test_extra_session_on_host():
    red_agent = DroneRedAgent
    blue_agent = SleepAgent
    sg = DroneSwarmScenarioGenerator(num_drones=18, starting_num_red=0,
                                     default_red_agent=red_agent,
                                     all_external=True, maximum_steps=500,
                                     max_length_data_links=25)
    cyborg = CybORG(sg, agents={f'blue_agent_{agent}': blue_agent(name=f'blue_agent_{agent}') for agent in
                                range(sg.num_drones)}, seed=123)

    for i in range(500):
        try:
            cyborg.step()
        except Exception as e:
            print(i)
            pprint({a: cyborg.get_last_action(a) for a in cyborg.active_agents})
            raise e
