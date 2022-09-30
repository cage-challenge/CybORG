from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction
from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import lo
from CybORG.Simulator.Host import Host
from CybORG.Simulator.State import State


class Portscan(ConcreteAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address, target_session: int):
        super().__init__(session, agent)
        self.ip_address = ip_address
        self.target_session = target_session

    def sim_execute(self, state: State) -> Observation:
        self.state = state
        obs = Observation()
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        from_host = state.sessions['Red'][self.session].host
        session = state.sessions['Red'][self.session]

        if not session.active:
            obs.set_success(False)
            return obs
        if self.ip_address == lo:
            target_host: Host = state.hosts[from_host]
            ports = ['all']
        else:
            target_host: Host = state.hosts[state.ip_addresses[self.ip_address]]
            ports = self.check_routable([state.subnets[i.subnet] for i in state.hosts[from_host].interfaces if i.ip_address != lo], [s for s in state.subnets.values() if self.ip_address in s.cidr])

        if ports is None or ports == []:
            obs.set_success(False)
            return obs

        obs.set_success(True)

        for process in target_host.processes:
            for conn in process.connections:
                if 'local_port' in conn and (conn['local_port'] in ports or 'all' in ports) and 'remote_port' not in conn:
                    from_subnet, to_subnet = ports[conn['local_port']] if conn['local_port'] in ports else ports['all']
                    # calculate the originating ip address
                    for i in state.hosts[from_host].interfaces:
                        if i.ip_address != lo:
                            if i.subnet == from_subnet:
                                originating_ip_address = i.ip_address
                    # internal so avoids nacls
                    obs.add_process(hostid=str(self.ip_address), local_port=conn["local_port"], local_address=self.ip_address)
                    target_host.events['NetworkConnections'].append({'local_address': self.ip_address,
                                                                     'local_port': conn["local_port"],
                                                                     'remote_address': originating_ip_address,
                                                                     'remote_port': target_host.get_ephemeral_port()})
        return obs
