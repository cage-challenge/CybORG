from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.State import State


class GetDroneSwarmData(RemoteAction):
    """Gets data from the other drones in the swarm"""

    def __init__(self, session, agent):
        super(GetDroneSwarmData, self).__init__(session, agent)

    def execute(self, state: State) -> Observation:
        if self.session in state.sessions[self.agent]:
            obs = Observation(True)
            hostname = state.sessions[self.agent][self.session].hostname
            host = state.hosts[hostname]
            interfaces = [interface for interface in host.interfaces if interface.swarm]
            obs.data[hostname] = {'System info':
                                      {"Hostname": hostname,
                                       'position': host.position}
                                  }
            for interface in interfaces:
                if "Interface" in obs.data[hostname]:
                    obs.data[hostname]["Interface"].append({"IP Address": interface.ip_address,
                                                            "Subnet": interface.subnet,
                                                            "blocked_ips": [{h_name: ip_addr for ip_addr, h_name in
                                                                             state.ip_addresses.items()}[i] for i in
                                                                            state.blocks.get(hostname, [])]})
                else:
                    obs.data[hostname]["Interface"] = [{"IP Address": interface.ip_address,
                                                        "Subnet": interface.subnet,
                                                        "blocked_ips": [{h_name: ip_addr for ip_addr, h_name in
                                                                         state.ip_addresses.items()}[i] for i in
                                                                        state.blocks.get(hostname, [])]}]

            for other_hostname, other_host in state.hosts.items():
                if other_hostname != hostname:
                    if self.check_routable(state, other_hostname, hostname):
                        obs.data[other_hostname] = {'System info':
                                                        {"Hostname": other_hostname,
                                                         'position': other_host.position}
                                                    }
                    else:
                        obs.data[other_hostname] = {'System info': {"Hostname": other_hostname}}
                    interfaces = [interface for interface in other_host.interfaces if interface.swarm]
                    for interface in interfaces:
                        if "Interface" in obs.data[other_hostname]:
                            obs.data[other_hostname]["Interface"].append({"IP Address": interface.ip_address,
                                                                          "Subnet": interface.subnet})
                        else:
                            obs.data[other_hostname]["Interface"] = [{"IP Address": interface.ip_address,
                                                                      "Subnet": interface.subnet}]

            for session_id, session_obj in state.sessions[self.agent].items():
                obs.add_session_info(hostid=session_obj.hostname, session_id=session_obj.ident,
                                     session_type=session_obj.session_type, agent=session_obj.agent,
                                     username=session_obj.username)
            obs.data[hostname]['Interface'][0]['NetworkConnections'] = host.events['NetworkConnections']
            host.events['NetworkConnections'] = []
            if len(host.events['ProcessCreation']) > 0:
                obs.data[hostname]['Processes'] = host.events['ProcessCreation']
                host.events['ProcessCreation'] = []
            return obs
        else:
            return Observation(False)
