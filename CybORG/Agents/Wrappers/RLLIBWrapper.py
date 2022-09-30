import inspect
import numpy as np
from ray.rllib.agents import ppo
from ray.tune import register_env
from CybORG import CybORG
from CybORG.agents import B_lineAgent, GreenAgent
from CybORG.agents.wrappers import ChallengeWrapper

class RLlibWrapper(ChallengeWrapper):
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

def env_creator(env_config: dict):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Shared/Scenarios/Scenario1b.yaml'
    agents = {"Red": B_lineAgent, "Green": GreenAgent}
    cyborg = CybORG(scenario_file=path, environment='sim', agents=agents)
    env = RLlibWrapper(env=cyborg, agent_name="Blue,", max_steps=100)
    return env

def print_results(results_dict):
    train_iter = results_dict["training_iteration"]
    r_mean = results_dict["episode_reward_mean"]
    r_max = results_dict["episode_reward_max"]
    r_min = results_dict["episode_reward_min"]
    print(f"{train_iter:4d} \tr_mean: {r_mean:.1f} \tr_max: {r_max:.1f} \tr_min: {r_min: .1f}")

if __name__ == "__main__":
    register_env(name="CybORG", env_creator=env_creator)
    config = ppo.DEFAULT_CONFIG.copy()
    agent = ppo.PPOTrainer(config=config, env="CybORG")

    train_steps = 1e6
    total_steps = 0
    while total_steps < train_steps:
        results = agent.train()
        print_results(results)
        total_steps = results["timesteps_total"]
