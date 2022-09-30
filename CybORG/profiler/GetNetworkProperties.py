import numpy as np
from networkx import number_connected_components, adjacency_matrix

from CybORG import CybORG
from CybORG.Shared.Actions.Action import RemoteAction
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


def get_network_properties(number_of_drones, maximum_steps, max_length_data_links, number_of_repeats=100):
    sg = DroneSwarmScenarioGenerator(num_drones=number_of_drones, starting_num_red=0, max_length_data_links=max_length_data_links)
    cyborg = CybORG(sg)
    connections = np.zeros((number_of_repeats,maximum_steps,number_of_drones))
    num_components = np.zeros((number_of_repeats,maximum_steps))
    max_route_length = np.zeros((number_of_repeats,maximum_steps))

    for j in range(number_of_repeats):
        for i in range(maximum_steps):
            cyborg.step()
            # get and log network properties
            # get connections per drone
            connections[j][i] = ([len(interface.data_links) for host in cyborg.environment_controller.state.hosts.values() for interface in host.interfaces if interface.swarm])
            # get all routes
            hosts = list(cyborg.environment_controller.state.hosts.keys())
            for index, host in enumerate(hosts):
                for other_host in hosts[index+1:]:
                    route = RemoteAction.get_route(cyborg.environment_controller.state, other_host, host)
                    if route is not None:
                        max_route_length[j][i] = max(len(route), max_route_length[j][i] )
            num_components[j][i] = number_connected_components(cyborg.environment_controller.state.link_diagram)
        cyborg.reset()
    return connections, max_route_length, num_components


if __name__ == "__main__":
    connections_total = []
    max_route_length_total = []
    connectivity_total = []
    connections_std = []
    max_route_length_std = []
    connectivity_std = []
    # for i in range(100):
    connections, max_route_length, connectivity = get_network_properties(15, 500, max_length_data_links=15, number_of_repeats=100)
        # print(connections.mean(axis=(0,2)), connections.std(axis=(0,2)))
        # connections_total.append(connections.mean())
        # connections_std.append(connections.std())
        # max_route_length_total.append(max_route_length.mean())
        # max_route_length_std.append(max_route_length.std())
        # connectivity_total.append(connectivity.mean())
        # connectivity_std.append(connectivity.std())
    import plotly.express as px

    fig = px.scatter(x=list(range(500)), y=connections.mean(axis=(0,2)), error_y=connections.std(axis=(0,2)), log_y=False, labels={"x": "Steps", "y": "Number of connections per drone", })
    fig.show()
    fig = px.scatter(x=list(range(500)), y=max_route_length.mean(axis=0), error_y=max_route_length.std(axis=0), log_y=False, labels={"x": "Steps", "y": "Length of longest route", })
    fig.show()
    fig = px.scatter(x=list(range(500)), y=connectivity.mean(axis=0), error_y=connectivity.std(axis=0), log_y=False, labels={"x": "Steps", "y": "Number of connected components", })
    fig.show()
