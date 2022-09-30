from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Shared import Results
from CybORG.Shared.Actions import Monitor, Remove, Restore


class BlueReactRemoveAgent(BaseAgent):
    def __init__(self):
        self.host_list = []
        self.last_action = None

    def train(self, results: Results):
        pass

    def get_action(self, observation, action_space):
        # add suspicious hosts to the hostlist if monitor found something
        # added line to allow for automatic monitoring.
        if self.last_action is not None and self.last_action == 'Monitor':
            for host_name, host_info in [(value['System info']['Hostname'], value) for key, value in observation.items() if key != 'success']:
                if host_name not in self.host_list and host_name != 'User0' and 'Processes' in host_info and len([i for i in host_info['Processes'] if 'PID' in i]) > 0:
                    self.host_list.append(host_name)
        # assume a single session in the action space
        session = list(action_space['session'].keys())[0]
        if len(self.host_list) == 0:
            self.last_action = 'Monitor'
            return Monitor(agent='Blue', session=session)
        else:
            self.last_action = 'Remove'
            return Remove(hostname=self.host_list.pop(0), agent='Blue', session=session)

    def end_episode(self):
        self.host_list = []
        self.last_action = None

    def set_initial_values(self, action_space, observation):
        pass


class BlueReactRestoreAgent(BaseAgent):
    def __init__(self):
        self.host_list = []
        self.last_action = None

    def train(self, results: Results):
        pass

    def get_action(self, observation, action_space):
        # add suspicious hosts to the hostlist if monitor found something
        # added line to reflect changes in blue actions
        if self.last_action is not None and self.last_action == 'Monitor':
            for host_name, host_info in [(value['System info']['Hostname'], value) for key, value in observation.items() if key != 'success']:
                if host_name not in self.host_list and host_name != 'User0' and 'Processes' in host_info and len([i for i in host_info['Processes'] if 'PID' in i]) > 0:
                    self.host_list.append(host_name)
        # assume a single session in the action space
        session = list(action_space['session'].keys())[0]
        if len(self.host_list) == 0:
            self.last_action = 'Monitor'
            return Monitor(agent='Blue', session=session)
        else:
            self.last_action = 'Restore'
            return Restore(hostname=self.host_list.pop(0), agent='Blue', session=session)

    def end_episode(self):
        self.host_list = []
        self.last_action = None

    def set_initial_values(self, action_space, observation):
        pass
