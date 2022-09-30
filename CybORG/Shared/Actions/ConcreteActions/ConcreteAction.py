from typing import List

from CybORG.Shared.Actions import Action
from CybORG.Simulator.Subnet import Subnet
from CybORG.Simulator.State import State


class ConcreteAction(Action):
    """
    Abstract class for all actions that directly simulate real world commands/tools.

    Any action attempting to simulate a real world command or tool should inherit from this class or one of its
    children.
    """
    def __init__(self,session: int,agent: str):
        super().__init__()
        self.agent = agent
        self.session = session

    def check_routable(self, from_subnets: List[Subnet], to_subnets: List[Subnet]) -> dict:
        """
        Checks which ports in from_subnets can be accessed by hosts in to_subnets.

        Checks NACL data to see if any ports are blocked.
        """
        # check what ports from subnets allow to any to subnets
        ports = {} # port: (to_subnet, from_subnet)
        for from_subnet in from_subnets:
            for to_subnet in to_subnets:
                # check if traffic from subnet is stopped by to subnet nacl
                if from_subnet.name in to_subnet.nacls:
                    if 'ICMP' not in ports:
                       ports['ICMP'] = (from_subnet.cidr, to_subnet.cidr)
                    if 'all' in to_subnet.nacls[from_subnet.name]['in']:
                        # if all ports accepted in then set ports to all and we are done
                        return {'all': (from_subnet.cidr, to_subnet.cidr)}
                    elif 'None' in to_subnet.nacls[from_subnet.name]['in']:
                        # If you don't have access to Enteprise network, you can't act on Operational Host
                        # TODO refactor this hacky fix
                        permission = self.check_for_enterprise_sessions()
                        ports = {'all': (from_subnet.cidr, to_subnet.cidr)} if permission else {}
                        return ports
                        
                    else:
                        # we only add the ports in rules to our accepted ports
                        for rule in to_subnet.nacls[from_subnet.name]['in']:
                            if rule['PortRange'] is int and rule['PortRange'] not in ports:
                                ports[rule["PortRange"]] = (from_subnet.cidr, to_subnet.cidr)
                            else:
                                for p in range(rule["PortRange"][0], rule["PortRange"][1]):
                                    if p not in ports:
                                        ports[p] = (from_subnet.cidr, to_subnet.cidr)
                elif 'all' in to_subnet.nacls:
                    if 'ICMP' not in ports:
                        ports['ICMP'] = (from_subnet.cidr, to_subnet.cidr)
                    # if all ports accepted out then use inbound rules only
                    if 'all' in to_subnet.nacls['all']['in']:
                        # if all ports accepted in then set ports to all and we are done
                        return {'all': (from_subnet.cidr, to_subnet.cidr)}
                    else:
                        # we only add the ports in rules to our accepted ports
                        for rule in to_subnet.nacls['all']['in']:
                            if rule['PortRange'] is int and rule['PortRange'] not in ports:
                                ports[rule["PortRange"]] = (from_subnet.cidr, to_subnet.cidr)
                            else:
                                for p in range(rule["PortRange"][0], rule["PortRange"][1]):
                                    if p not in ports:
                                        ports[p] = (from_subnet.cidr, to_subnet.cidr)
                else:
                    # this means that traffic cannot reach move between these 2 subnets
                    continue

        return ports

    def check_for_enterprise_sessions(self):
        permission = False
        for session_id in self.state.sessions[self.agent]:
            session = self.state.sessions[self.agent][session_id]
            if 'Enterprise' in session.host:
                permission = True

        return permission


