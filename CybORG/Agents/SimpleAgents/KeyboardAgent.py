# Copyright DST Group. Licensed under the MIT license.
import inspect
from pprint import pprint
from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent

from ipaddress import IPv4Network


class KeyboardAgent(BaseAgent):

    def __init__(self,screen_width=94):
        self.step = 1
        self.screen_width = screen_width # Sets width of the printed bars

    def get_action(self, observation, action_space, sessions=None):
        self._print_observation(observation)
        self._print_action_success(observation)

        valid_commands = self._get_valid_commands(action_space)
        command = self._choose_from_options('Command',list(valid_commands.keys()))
        action = self._select_parameters(valid_commands[command])
        
        self.step += 1
        return action

    def _print_observation(self,observation):
        print('',f' Turn {self.step}: Observation '.center(self.screen_width, '*'),'',sep='\n')
        if type(observation) == dict:
            pprint(observation)
        else:
            print(observation)

    def _print_action_success(self,observation):
        if type(observation) == dict:
            success = observation['success']
        else:
            success = observation.success

        if self.step == 1:
            pass
        elif success.value==1:
            print(self.screen_width * '-', 'Yay! The Action was a Success!', self.screen_width * '*', sep='\n')
        elif success.value == 2:
            print(self.screen_width * '-', 'Outcome of action is unknown...', self.screen_width * '*', sep='\n')
        else:
            print(self.screen_width * '-', 'The action failed!', self.screen_width * '*', sep='\n')

    def _get_valid_commands(self,action_space):
        print('',f' Turn {self.step}: Command Selection '.center(self.screen_width, '*'),'',sep='\n')
        valid_commands = {}
        for command in action_space['action'].keys():
            parameter_list = inspect.getfullargspec(command).args 
            parameter_dict = {}
            for parameter in parameter_list:
                if parameter == 'self':
                    continue
                if parameter == 'priority':
                    continue

                option_dict = action_space[parameter]
                filter_f = lambda key : option_dict[key]
                valid_options = list(filter(filter_f,option_dict.keys()))
                if not valid_options:
                    break
                parameter_dict[parameter] = valid_options

            else:
                parameter_dict['command'] = command
                valid_commands[command.__name__] = parameter_dict

        return valid_commands

    def _choose_from_options(self, name:str, options:list):
        if len(options) == 0:
            raise ValueError(f'Selecting {name} failed because there are no valid options')
        elif len(options) == 1:
            choice = options[0]
            print(f'Automatically choosing {choice} as it is the only option.')
            return choice

        for i in range(len(options)):
            print(i, options[i])

        while True:
            user_input = input(self.screen_width*'-'+f'\nCHOOSE A {name.upper()}: ')
            if user_input.isdigit():
                try:
                    choice = options[int(user_input)]
                    break
                except:
                    print('Choose a number in range.....')
            else:
                options_lower = [str(x).lower() for x in options]
                try:
                    index = options_lower.index(user_input.lower())
                    choice = options[index]
                except:
                    print(f'You didn\'t type in a valid {name}...')

        print(f'You chose {choice}.')
        return choice

    def _select_parameters(self, parameter_dict):
        print('\n')
        print(f' Turn {self.step}: Parameter Selection '.center(self.screen_width, '*'))
        print('\n')

        command = parameter_dict.pop('command')

        chosen_parameters = {}
        for parameter in parameter_dict:
            print(f' {parameter.capitalize()} Selection '.center(self.screen_width, '-'))
            choice = self._choose_from_options('Parameter',parameter_dict[parameter])
            chosen_parameters[parameter] = choice
            
        return command(**chosen_parameters)

    def train(self, results):
        # The user trains with their brain, not an API!
        pass

    def set_initial_values(self, action_space, observation):
        pass

    def end_episode(self):
        pass

