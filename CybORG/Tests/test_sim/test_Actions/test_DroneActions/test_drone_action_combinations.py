from CybORG import CybORG
from CybORG.Agents import SleepAgent

# test block comms and remote action
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic, AllowTraffic
from CybORG.Simulator.Actions.ConcreteActions.EscalateActions.SeizeControl import SeizeControl
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitDroneVulnerability import ExploitDroneVulnerability
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions

# TODO add more tests for observations
# TODO test if too much traffic fails actions
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator
from CybORG.Tests.utils import AlwaysTrueGenerator


def test_simultaneous_block_and_exploit(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    # simultaneous block and exploit results in block not succeeding
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         target_agent: BlockTraffic(agent=target_agent, session=0, ip_address=red_ip)})

    assert obs[red_agent]['success'] == True
    assert 'Sessions' in obs[red_agent].get(target_host, {})
    assert len(obs[red_agent][target_host]['Sessions']) == 1

    assert obs[target_agent]['success'] == True
    assert 'blocked_ips' in obs[target_agent][target_host]['Interface'][0]
    assert red_ip in obs[target_agent][target_host]['Interface'][0]['blocked_ips']

    # subsequent exploit fails in future attempts without blue needing to reimpose the block
    obs, rew, done, info = cyborg.parallel_step({red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip)})

    assert obs[red_agent]['success'] == False
    assert 'Sessions' in obs[red_agent].get(target_host, {})
    assert len(obs[red_agent][target_host]['Sessions']) == 1


    # allows actions to get through the fire wall on the next turn
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         target_agent: AllowTraffic(agent=target_agent, session=0, ip_address=red_ip)})

    assert obs[red_agent]['success'] == False
    assert 'Sessions' in obs[red_agent].get(target_host, {})

    assert obs[target_agent]['success'] == True
    assert red_ip not in obs[target_agent][target_host]['Interface'][0].get('blocked_ips', {})

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip)})

    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert 'Sessions' not in obs[red_agent].get(target_host, {})
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"



# test exploit action and remove
def test_simultaneous_remove_and_exploit(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    # demonstrate remove does remove an incoming attack after it is successful
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         target_agent: RemoveOtherSessions(agent=target_agent, session=0)})

    assert obs[red_agent]['success'] == True
    assert 'Sessions' in obs[red_agent].get(target_host, {}), obs
    assert obs[target_agent]['success'] == True

    # remove prevents seize control
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip)})

    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    assert obs[red_agent]['success'] == False
    assert 'Sessions' not in obs[red_agent].get(target_host, {})

    # red is still able to reexploit and seize control
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip)})

    assert obs[red_agent]['success'] == True
    assert 'Sessions' in obs[red_agent].get(target_host, {})

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip)})

    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert 'Sessions' not in obs[red_agent].get(target_host, {})
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"


# test seize control and remove
def test_simultaneous_remove_and_seize(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    obs, rew, done, info = cyborg.parallel_step({red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip),
                                    target_agent: RemoveOtherSessions(agent=target_agent, session=0)})

    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    assert obs[red_agent]['success'] == False
    assert 'Sessions' not in obs[red_agent].get(target_host, {})

# test seize control and retake control
def test_simultaneous_seize_and_retake(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    obs, rew, done, info = cyborg.parallel_step({red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip),
                                    blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)})
    assert target_agent in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] not in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert obs[blue_agent]['success'] == True
    assert 'Sessions' not in obs[red_agent].get(target_host, {})

# test seize control and retake control
def test_simultaneous_seize_and_retake_self(attacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    obs, rew, done, info = cyborg.parallel_step({red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip),
                                    target_agent: RetakeControl(agent=target_agent, session=0, ip_address=target_ip)})
    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert obs[target_agent]['success'] == False
    assert 'Sessions' not in obs[red_agent].get(target_host, {})

# test exploit drone and retake control
def test_simultaneous_expoit_and_retake(unattacked_blue):
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    red_obs = cyborg.get_observation(target_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)})
    assert obs[red_agent]['success'] == True
    assert obs[blue_agent]['success'] == False
    assert 'Sessions' in obs[red_agent].get(target_host, {})

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip)})

    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert 'Sessions' not in obs[red_agent].get(target_host, {})


def test_simultaneous_block_on_path_and_exploit():
    # impose a block on the path between the target and red host
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=0, max_length_data_links=10,
                                     default_red_agent=SleepAgent, red_internal_only=False,
                                     starting_positions=[[50, 42],[50,50],[50,58]],
                                     agent_to_drone_mapping = {2: 'Red'}, red_spawn_rate=0.)
    cyborg = CybORG(scenario_generator=sg, seed=AlwaysTrueGenerator())
    red_agent = 'red_agent_2'
    blue_agent = 'blue_agent_1'
    target_agent = 'blue_agent_0'
    target_obs = cyborg.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']

    # check that DroneSwarmScenarioGenerator has created a line
    assert [i for i in cyborg.environment_controller.state.link_diagram.edges] == [('drone_0', 'drone_0'), ('drone_0', 'drone_1'), ('drone_1', 'drone_1'), ('drone_1', 'drone_2'), ('drone_2', 'drone_2')]

    red_obs = cyborg.get_observation(red_agent)
    red_obs = [obs for obs in red_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    red_ip = red_obs['Interface'][0]['IP Address']

    # simultaneous block and exploit results in block failing
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         blue_agent: BlockTraffic(agent=blue_agent, session=0, ip_address=red_ip)})

    assert obs[red_agent]['success'] == True
    assert 'Sessions' in obs[red_agent].get(target_host, {})
    assert  len(obs[red_agent][target_host]['Sessions']) == 1

    assert obs[blue_agent]['success'] == True
    assert 'blocked_ips' in obs[blue_agent]['drone_1']['Interface'][0]
    assert red_ip in obs[blue_agent]['drone_1']['Interface'][0]['blocked_ips']

    # exploit then fails in future attempts without blue needing to reimpose the block
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip)})

    assert obs[red_agent]['success'] == False
    assert len(obs[red_agent][target_host]['Sessions']) == 1

    # allows actions to get through the fire wall on the next turn
    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip),
         blue_agent: AllowTraffic(agent=blue_agent, session=0, ip_address=red_ip)})

    assert obs[red_agent]['success'] == False
    assert 'Sessions' in obs[red_agent].get(target_host, {})
    assert  len(obs[red_agent][target_host]['Sessions']) == 1

    assert obs[blue_agent]['success'] == True
    assert red_ip not in obs[blue_agent][target_host]['Interface'][0].get('blocked_ips', {})

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip)})

    assert obs[red_agent]['success'] == True
    assert 'Sessions' in obs[red_agent].get(target_host, {})
    assert  len(obs[red_agent][target_host]['Sessions']) == 2

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: SeizeControl(agent=red_agent, session=0, ip_address=target_ip)})

    assert target_agent not in cyborg.active_agents
    assert 'red_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert obs[red_agent]['success'] == True
    assert 'Sessions' not in obs[red_agent].get(target_host, {})
    assert len(cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('red_agent_' + target_agent.split('_')[-1])['session']}"

def test_simultaneous_block_on_path_and_retake():
    # impose a block on the path between the target and red host
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=0, max_length_data_links=10,
                                     default_red_agent=SleepAgent, red_internal_only=False,
                                     starting_positions=[[50, 42],[50,50],[50,58]],
                                     agent_to_drone_mapping = {2: 'Red', 1: 'Red'}, red_spawn_rate=0.)
    cyborg = CybORG(scenario_generator=sg, seed=1)
    target_agent = 'red_agent_2'
    red_agent = 'red_agent_1'
    blue_agent = 'blue_agent_0'
    target_obs = cyborg.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']

    # check that DroneSwarmScenarioGenerator has created a line
    assert [i for i in cyborg.environment_controller.state.link_diagram.edges] == [('drone_0', 'drone_0'), ('drone_0', 'drone_1'), ('drone_1', 'drone_1'), ('drone_1', 'drone_2'), ('drone_2', 'drone_2')]

    blue_ip = cyborg.get_observation(blue_agent)
    blue_ip = [obs for obs in blue_ip.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    blue_ip = blue_ip['Interface'][0]['IP Address']

    # simultaneous block and exploit results in exploit passing
    obs, rew, done, info = cyborg.parallel_step(
        {blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip),
         red_agent: BlockTraffic(agent=red_agent, session=0, ip_address=blue_ip)})

    assert obs[blue_agent]['success'] == True

    assert obs[red_agent]['success'] == True
    assert 'blocked_ips' in obs[red_agent]['drone_1']['Interface'][0]
    assert blue_ip in obs[red_agent]['drone_1']['Interface'][0]['blocked_ips']

    # exploit also fails in future attempts without blue needing to reimpose the block
    obs, rew, done, info = cyborg.parallel_step(
        {blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)})

    assert obs[blue_agent]['success'] == False

    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=0, max_length_data_links=10,
                                     default_red_agent=SleepAgent, red_internal_only=False,
                                     starting_positions=[[50, 42],[50,50],[50,58]],
                                     agent_to_drone_mapping = {2: 'Red', 1: 'Red'}, red_spawn_rate=0.)
    cyborg = CybORG(scenario_generator=sg, seed=1)

    obs, rew, done, info = cyborg.parallel_step(
        {red_agent: BlockTraffic(agent=red_agent, session=0, ip_address=blue_ip)})

    assert obs[red_agent]['success'] == True
    assert 'blocked_ips' in obs[red_agent]['drone_1']['Interface'][0]
    assert blue_ip in obs[red_agent]['drone_1']['Interface'][0]['blocked_ips']

    # exploit also fails in future attempts without blue needing to reimpose the block
    obs, rew, done, info = cyborg.parallel_step(
        {blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)})

    assert obs[blue_agent]['success'] == False

    # allows actions to get through the fire wall on the following turn
    obs, rew, done, info = cyborg.parallel_step(
        {blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip),
         red_agent: AllowTraffic(agent=red_agent, session=0, ip_address=blue_ip)})

    assert obs[blue_agent]['success'] == False
    assert target_agent in cyborg.active_agents

    assert obs[red_agent]['success'] == True
    assert blue_ip not in obs[blue_agent][target_host]['Interface'][0].get('blocked_ips', {})

    obs, rew, done, info = cyborg.parallel_step(
        {blue_agent: RetakeControl(agent=blue_agent, session=0, ip_address=target_ip)})

    assert obs[blue_agent]['success'] == True

    assert target_agent not in cyborg.active_agents
    assert 'blue_agent_' + target_agent.split('_')[-1] in cyborg.active_agents
    assert len(cyborg.get_action_space('blue_agent_' + target_agent.split('_')[-1])[
                   'session']) > 0, f"{cyborg.get_action_space('blue_agent_' + target_agent.split('_')[-1])['session']}"
