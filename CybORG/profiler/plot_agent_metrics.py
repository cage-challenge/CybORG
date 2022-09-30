import json
import plotly.express as px
import pandas as pd
import plotly.graph_objects as go
import numpy as np
pd.options.plotting.backend = "plotly"

# https://stackoverflow.com/questions/10058227/calculating-mean-of-arrays-with-different-lengths
def tolerant_mean(arrs):
    lens = [len(i) for i in arrs]
    arr = np.ma.empty((np.max(lens),len(arrs)))
    arr.mask = True
    for idx, l in enumerate(arrs):
        arr[:len(l),idx] = l
    return arr.mean(axis=-1)
def tolerant_max(arrs):
    lens = [len(i) for i in arrs]
    arr = np.ma.empty((np.max(lens),len(arrs)))
    arr.mask = True
    for idx, l in enumerate(arrs):
        arr[:len(l),idx] = l
    return arr.max(axis=-1)
def tolerant_min(arrs):
    lens = [len(i) for i in arrs]
    arr = np.ma.empty((np.max(lens),len(arrs)))
    arr.mask = True
    for idx, l in enumerate(arrs):
        arr[:len(l),idx] = l
    return arr.min(axis=-1)

if __name__ == "__main__":
    # to_show = ['blue_reward']
    # to_show = ['average_bandwidth_usage', 'maximum_bandwidth_usage']
    # to_show = ['green_action_success', 'blue_action_success', 'red_action_success']
    # to_show = ['green_action_failures', 'blue_action_failures', 'red_action_failures']
    # to_show = ['num_red']
    # to_show = ['average_game_length','minimum_game_length', 'maximum_game_length' ]
    # to_show = ['average_game_length','minimum_game_length', 'maximum_game_length' ]
    to_show_per_num_drone_per_agent = ['average_episodic_blue_reward', 'average_bandwidth_usage', 'maximum_bandwidth_usage',
                             'blue_action_success', 'red_action_success',
                             'green_action_failures', 'fps',
                             'average_game_length', 'minimum_game_length', 'maximum_game_length',
                             'average_valid_red_actions', 'maximum_valid_red_actions', 'minimum_valid_red_actions',
                             'average_num_red_agents_per_episode']
    to_show_per_num_drone_per_agent = []
    to_show_bar_graph = ['green_action_distributions', 'blue_action_distributions', 'red_action_distributions']
    to_show_bar_graph = []
    to_show_per_num_drone = ['num_components', 'max_route_length', 'connections']
    to_show_per_step_per_agent = ['blue_reward_per_drone', 'valid_red_actions', 'average_dropped_actions',
                        'average_routeless_actions', 'average_num_red_agents', 'average_bandwidth_usage', 'maximum_bandwidth_usage']
    # to_show_per_num_drone = []
    to_show_per_step_per_agent = []
    to_show_per_step = ['num_components', 'max_route_length', 'connections']
    with open('agent_behaviour.data', 'r') as f:
        data = json.load(f)
    print(len(data))
    df = pd.DataFrame(data)
    print(df.columns)
    # df['fps'] = 1/df['step_time']
    # for variable in ['number_of_drones']:
    #     dfa = df.groupby(variable)
    #     # for axis in ['routeless_actions', 'step_time', 'fps', 'connections',
    #     #                'max_route_length', 'num_components']:
    #     #     dfa[axis].mean().plot().show()
    #     for axis in ['action_success', 'actions']:
    #         pass

    # for axis in ['dropped_actions', 'routeless_actions',
    #                'reward', 'cummulative_reward', 'step_time', 'fps', 'blue_agents', 'game_length']:
    #     # dfa = df.groupby(['step_number']).mean()
    #     fig = go.Figure()
    #     for component, group in df.groupby(['red_agent', 'blue_agent']):
    #         y = group.groupby('step_number')[axis].mean()
    #         fig.add_trace(go.Scatter(x=list(range(len(y))), y=y, name=f'{component[0]} {component[1]}', mode='markers'))
    #     fig.update_layout(
    #         title=axis,
    #         xaxis_title="Step number",
    #         yaxis_title=axis,
    #     )
    #     fig.show()

    # fig = px.box(df, x='blue_agent', y='game_length', points='all')
    # fig.update_layout(
    #     title='Game length',
    #     xaxis_title="Blue agent",
    #     yaxis_title='Game length',
    # )
    # fig.show()
    for axis in ['cummulative_reward', 'bandwidth_usage', 'num_components', 'dropped_green_actions', 'blocked_green_actions', 'routeless_green_actions', 'compromised_comms', 'game_length']:
        fig = go.Figure()
        for component, group in df.groupby(['blue_agent', 'red_agent']):
            fig.add_trace(go.Box(y=group[axis], name=f'{component[0]} {component[1]}'))
        fig.update_layout(
            title=axis,
            xaxis_title="agent_combinations",
            yaxis_title=axis,
        )
        fig.show()
        # fig = go.Figure()
        # for component, group in df.groupby(['red_agent', 'blue_agent']):
        #     fig.add_trace(go.Box(y=group[axis], name=f'{component[0]} {component[1]}'))
        # fig.update_layout(
        #     title=axis,
        #     xaxis_title="agent_combinations",
        #     yaxis_title=axis,
        # )
        # fig.show()

    # for variable in ['step_number']:
    #     for axis in ['dropped_actions', 'routeless_actions',
    #                    'bandwidth_usage', 'reward', 'cummulative_reward', 'step_time', 'connections',
    #                    'max_route_length', 'num_components', 'blue_agents', 'game_length']:
    #         for component, group in df.groupby('number_of_drones'):
    #             fig=go.Figure()
    #             fig.add_trace(go.Scatter(x=group[variable], y=group[axis], name=component))
    #             fig.show()
    #     for axis in ['action_success', 'actions']:
    #         pass
