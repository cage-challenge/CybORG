# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.RewardCalculator import RewardCalculator

WIN_REWARD = 1
LOSE_REWARD = -1

REWARD_MAX_DECIMAL_PLACES = 3

REWARD_DIFF_SCALE_FACTOR = 1000


class BaselineRewardCalculator(RewardCalculator):
    def __init__(self, agent_name: str):
        super().__init__(agent_name)
        self.previous_diff = 0
        self.flat = True

    def calculate_reward(self, current_state: dict, action: Action, agent_observations: dict, done: bool):
        reward = 0

        if done:
            # check for win
            win = True
            for key, host in current_state.items():
                if key != "success" and isinstance(host, dict):
                    for session in host.get("Sessions", []):
                        if "Agent" in session and session["Agent"] == "Red":
                            win = False
                            break
                if not win:
                    break
            # check for win or loss
            if win:
                reward += WIN_REWARD
            else:
                reward += LOSE_REWARD

        current_diff = 0
        for i in range(len(self.init_state)):
            if self.init_state[i] != flat_fixed_state[i]:
                current_diff -= 1

        # Code for calculating reward with recursive methods.
        # Note that self.init_state will need to be an observation
        # rather than a flat fixed list for this to work
        #
        # current_diff = self.obs_diff(self.init_state.get_dict(),
        #                              current_state.get_dict())

        diff = (current_diff - self.previous_diff)
        reward += diff / REWARD_DIFF_SCALE_FACTOR
        self.previous_diff = current_diff

        self.previous_state = flat_fixed_state
        self.previous_obs = agent_observations
        self.tick()
        return round(reward, REWARD_MAX_DECIMAL_PLACES)

    # Method to find number of differences between two observations as
    # dictionaries
    def obs_diff(self, init, current):
        reward = 0
        if init == current:
            return reward
        list_init = {}
        list_current = {}
        val_init = {}
        val_current = {}
        shared_keys = []
        for k, v in current.items():
            if type(v) is dict:
                if k in init:
                    reward += self.obs_diff(init[k], current[k])
                    shared_keys.append(k)
                else:
                    reward -= 1 + self.obs_size(v)
            elif type(v) is list:
                list_current[k] = v
            else:
                val_current[k] = v
        for k, v in init.items():
            if type(v) is dict:
                if k not in shared_keys:
                    reward -= 1 + self.obs_size(init[k])
            elif type(v) is list:
                list_init[k] = v

            else:
                val_init[k] = v

        for k, v in list_init.items():
            if k in list_current:
                for d_init in v:
                    for d_cur in list_current[k]:
                        if d_init == d_cur:
                            v.remove(d_init)
                            list_current[k].remove(d_cur)
                for i in range(len(v)):
                    if i < len(list_current[k]):
                        reward += self.obs_diff(v[i], list_current[k][i])
                    else:
                        reward -= self.obs_size(v[i])
                for i in range(len(v), len(list_current[k])):
                    reward -= self.obs_size(list_current[k][i])
                list_current.pop(k)
            else:
                reward -= 1
                for d in v:
                    reward -= self.obs_size(d)
        for k, v in list_current.items():
            reward -= 1
            for d in v:
                reward -= self.obs_size(d)

        reward -= len(dict(val_init.items() ^ val_current.items()))
        return reward

    # Method to find the size of an observation as a dictionary
    def obs_size(self, d):
        count = 0
        for k, v in d.items():
            if type(v) is dict:
                count += 1 + self.obs_size(v)
            elif type(v) is list:
                count += 1
                for i in v:
                    count += self.obs_size(i)
            else:
                count += 1
        return count
