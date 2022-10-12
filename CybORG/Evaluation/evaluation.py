import inspect
import subprocess
import time
from statistics import mean, stdev

from CybORG import CybORG, CYBORG_VERSION
from CybORG.Agents import RandomAgent
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator

MAX_EPS = 100


def wrap(env):
    return PettingZooParallelWrapper(env=env)


def get_git_revision_hash() -> str:
    return subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('ascii').strip()


if __name__ == "__main__":
    cyborg_version = CYBORG_VERSION
    scenario = 'Scenario3'
    # commit_hash = get_git_revision_hash()
    # ask for a name
    name = input('Name: ')
    # ask for a team
    team = input("Team: ")
    # ask for a name for the agent
    name_of_agent = input("Name of technique: ")

    lines = inspect.getsource(wrap)
    wrap_line = lines.split('\n')[1].split('return ')[1]

    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(sg, 'sim')
    wrapped_cyborg = wrap(cyborg)

    # Change this line to load your agents
    agents = {agent: RandomAgent() for agent in wrapped_cyborg.possible_agents}

    print(f'Using agents {agents}, if this is incorrect please update the code to load in your agent')

    file_name = str(inspect.getfile(CybORG))[:-7] + '/Evaluation/' + time.strftime("%Y%m%d_%H%M%S") + '.txt'
    print(f'Saving evaluation results to {file_name}')
    with open(file_name, 'a+') as data:
        data.write(f'CybORG v{cyborg_version}, {scenario}\n')
        data.write(f'author: {name}, team: {team}, technique: {name_of_agent}\n')
        data.write(f"wrappers: {wrap_line}\n")
        data.write(f"agent assignment: {agents}")

    print(f'using CybORG v{cyborg_version}, {scenario}\n')

    cyborg = CybORG(sg, 'sim')
    wrapped_cyborg = wrap(cyborg)


    total_reward = []
    actions_log = []
    for i in range(MAX_EPS):
        observations = wrapped_cyborg.reset()
        action_spaces = wrapped_cyborg.action_spaces
        r = []
        a = []
        # cyborg.env.env.tracker.render()
        for j in range(500):
            actions = {agent_name: agents[agent_name].get_action(observations[agent_name], action_spaces[agent_name]) for agent_name in wrapped_cyborg.agents}
            observations, rew, done, info = wrapped_cyborg.step(actions)
            if all(done.values()):
                break
            r.append(mean(rew.values()))
            a.append({agent_name: str(cyborg.get_last_action(agent_name)) for agent_name in wrapped_cyborg.agents})
        total_reward.append(sum(r))
        actions_log.append(a)
    print(f'Average reward is: {mean(total_reward)} with a standard deviation of {stdev(total_reward)}')
    with open(file_name, 'a+') as data:
        data.write(f'mean: {mean(total_reward)}, standard deviation {stdev(total_reward)}\n')
        for act, sum_rew in zip(actions_log, total_reward):
            data.write(f'actions: {act}, total reward: {sum_rew}\n')
