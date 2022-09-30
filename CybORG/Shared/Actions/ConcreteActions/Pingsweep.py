from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction
from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import lo_subnet, lo
from CybORG.Simulator.State import State


class Pingsweep(ConcreteAction):
    """
    Concrete action that simulates a pingsweep, returning a list of active ip addresses on a subnet.
    """
    def __init__(self, session: int,agent: str,target_session: int, subnet: IPv4Network):
        super().__init__(session,agent)
        self.target_session = target_session
        self.subnet = subnet

    def sim_execute(self, state: State) -> Observation:
        self.state = state
        """
        Executes a pingsweep in the simulator.
        """
        obs = Observation()

        # Check the session running the code exists and is active.
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        from_host = state.sessions[self.agent][self.session].host
        session = state.sessions[self.agent][self.session]
        if not session.active:
            obs.set_success(False)
            return obs

        # Check the target session exists and is active.
        if self.target_session in state.sessions[self.agent]:
            target_session = state.sessions[self.agent][self.target_session]
        else:
            obs.set_success(False)
            return obs
        if not target_session.active:
            obs.set_success(False)
            return obs

        # Collect ip addresses
        if self.subnet == lo_subnet:
            # Loopback address triviality
            obs.set_success(True)
            obs.add_interface_info(hostid=str(lo_subnet), subnet=lo_subnet, ip_address=lo)
        else:
            # Check NACL rules allow subnet to be scanned and ICMP is not banned.
            available_ports = self.check_routable([state.subnets[i.subnet] for i in state.hosts[from_host].interfaces if i.subnet != lo_subnet], [state.subnets[self.subnet]])
            if 'ICMP' not in available_ports and 'all' not in available_ports:
                obs.set_success(False)
                return obs
            # Return ip addresses.
            target_hosts = []
            for host in state.subnets[self.subnet].ip_addresses:
                obs.set_success(True)
                target_hosts.append(state.ip_addresses[host])
                obs.add_interface_info(hostid=str(host), ip_address=host, subnet=self.subnet)

        return obs
