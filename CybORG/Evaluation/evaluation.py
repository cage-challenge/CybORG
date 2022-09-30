import subprocess
import inspect
import time
from statistics import mean, stdev

from CybORG import CybORG, CYBORG_VERSION
from CybORG.Agents import B_lineAgent, SleepAgent, RandomAgent
from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
#from CybORG.Agents.SimpleAgents.BlueLoadAgent import BlueLoadAgent
from CybORG.Agents.SimpleAgents.BlueReactAgent import BlueReactRemoveAgent
from CybORG.Agents.SimpleAgents.Meander import RedMeanderAgent
from CybORG.Agents.Wrappers.EnumActionWrapper import EnumActionWrapper
from CybORG.Agents.Wrappers.FixedFlatWrapper import FixedFlatWrapper
from CybORG.Agents.Wrappers.OpenAIGymWrapper import OpenAIGymWrapper
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper

from CybORG.Agents.Wrappers import ChallengeWrapper

from CybORG.Simulator.Scenarios import FileReaderScenarioGenerator, DroneSwarmScenarioGenerator


MAX_EPS = 100
config = {'num_drones': 20,
          'max_length_data_links': 20}

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

    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario2.yaml'
    sg = DroneSwarmScenarioGenerator(**config)
    cyborg = CybORG(sg, 'sim')
    wrapped_cyborg = wrap(cyborg)

    # Change this line to load your agents
    agents = {agent: RandomAgent() for agent in wrapped_cyborg.possible_agents}

    print(f'Using agents {agents}, if this is incorrect please update the code to load in your agent')

    file_name = str(inspect.getfile(CybORG))[:-10] + '/Evaluation/' + time.strftime("%Y%m%d_%H%M%S") + '.txt'
    print(f'Saving evaluation results to {file_name}')
    with open(file_name, 'a+') as data:
        data.write(f'CybORG v{cyborg_version}, {scenario}\n')
        data.write(f'author: {name}, team: {team}, technique: {name_of_agent}\n')
        data.write(f"wrappers: {wrap_line}\n")
        data.write(f"agent assignment: {agents}")


    print(f'using CybORG v{cyborg_version}, {scenario}\n')
    for num_steps in [30, 50, 100]:
        for red_agent in [B_lineAgent, RedMeanderAgent, SleepAgent]:

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
                for j in range(num_steps):
                    actions = {agent_name: agents[agent_name].get_action(observations[agent_name], action_spaces[agent_name]) for agent_name in wrapped_cyborg.agents}
                    observations, rew, done, info = wrapped_cyborg.step(actions)
                    r.append(mean(rew.values()))
                    a.append({agent_name: str(cyborg.get_last_action(agent_name)) for agent_name in wrapped_cyborg.env.agents})
                    if all(done.values()):
                        break
                total_reward.append(sum(r))
                actions_log.append(a)
            print(f'Average reward for red agent {red_agent.__name__} and steps {num_steps} is: {mean(total_reward)} with a standard deviation of {stdev(total_reward)}')
            with open(file_name, 'a+') as data:
                data.write(f'steps: {num_steps}, adversary: {red_agent.__name__}, mean: {mean(total_reward)}, standard deviation {stdev(total_reward)}\n')
                for act, sum_rew in zip(actions_log, total_reward):
                    data.write(f'actions: {act}, total reward: {sum_rew}\n')
