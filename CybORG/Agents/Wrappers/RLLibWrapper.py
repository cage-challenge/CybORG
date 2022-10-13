import inspect
import numpy as np
from ray.rllib.agents import ppo
from ray.rllib.env import ParallelPettingZooEnv
from ray.tune import register_env
from CybORG import CybORG
from CybORG.Agents import B_lineAgent, GreenAgent
from CybORG.Agents.Wrappers import ChallengeWrapper

from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Scenarios import FileReaderScenarioGenerator, DroneSwarmScenarioGenerator


class RLLibWrapper(ChallengeWrapper):
    def init(self, agent_name, env, reward_threshold=None, max_steps=None):
        super().__init__(agent_name, env, reward_threshold, max_steps)

    def step(self, action=None):
        obs, reward, done, info = self.env.step(action=action)
        self.step_counter += 1
        if self.max_steps is not None and self.step_counter >= self.max_steps:
            done = True
        return np.float32(obs), reward, done, info

    def reset(self):
        self.step_counter = 0
        obs = self.env.reset()
        return np.float32(obs)


def env_creator_CC1(env_config: dict):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    agents = {"Red": B_lineAgent(), "Green": GreenAgent()}
    cyborg = CybORG(scenario_generator=sg, environment='sim', agents=agents)
    env = RLLibWrapper(env=cyborg, agent_name="Blue", max_steps=100)
    return env


def env_creator_CC2(env_config: dict):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario2.yaml'
    sg = FileReaderScenarioGenerator(path)
    agents = {"Red": B_lineAgent(), "Green": GreenAgent()}
    cyborg = CybORG(scenario_generator=sg, environment='sim', agents=agents)
    env = RLLibWrapper(env=cyborg, agent_name="Blue", max_steps=100)
    return env


def env_creator_CC3(env_config: dict):
    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(scenario_generator=sg, environment='sim')
    env = ParallelPettingZooEnv(PettingZooParallelWrapper(env=cyborg))
    return env


def print_results(results_dict):
    train_iter = results_dict["training_iteration"]
    r_mean = results_dict["episode_reward_mean"]
    r_max = results_dict["episode_reward_max"]
    r_min = results_dict["episode_reward_min"]
    print(f"{train_iter:4d} \tr_mean: {r_mean:.1f} \tr_max: {r_max:.1f} \tr_min: {r_min: .1f}")


if __name__ == "__main__":
    register_env(name="CC1", env_creator=env_creator_CC1)
    register_env(name="CC2", env_creator=env_creator_CC2)
    register_env(name="CC3", env_creator=env_creator_CC3)
    config = ppo.DEFAULT_CONFIG.copy()
    for env in ['CC1', 'CC2', 'CC3']:
        agent = ppo.PPOTrainer(config=config, env=env)

        train_steps = 1e2
        total_steps = 0
        while total_steps < train_steps:
            results = agent.train()
            print_results(results)
            total_steps = results["timesteps_total"]
