from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction



class GreenPortScan(ConcreteAction):
    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__(agent=agent,session=session)
        self.hostname = hostname

    def sim_execute(self, state) -> Observation:
        obs = Observation()
        obs.set_success(True)
        # find session inside or close to the target subnet
        session = self.session
        # Get the ip of the hostname
        ip_map = state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == self.hostname:
                self.ip_address = ip
                break
         
        from_host = state.sessions['Red'][self.session].host
        target_host: Host = state.hosts[state.ip_addresses[self.ip_address]]
        ports = ['all']
        for ip in ip_map:
            if ip_map[ip] == from_host:
                originating_ip_address = ip

        for process in target_host.processes:
            for conn in process.connections:
                if 'local_port' in conn and (conn['local_port'] in ports or 'all' in ports) and 'remote_port' not in conn:
                    obs.add_process(hostid=str(self.ip_address), local_port=conn["local_port"], local_address=self.ip_address)
                    target_host.events['NetworkConnections'].append({'local_address': self.ip_address,
                                                                     'local_port': conn["local_port"],
                                                                     'remote_address': originating_ip_address,
                                                                     'remote_port': target_host.get_ephemeral_port()})

        return obs

