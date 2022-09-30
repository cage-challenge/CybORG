from dataclasses import dataclass
from typing import Tuple, Union
from enum import Enum
from ipaddress import IPv4Address, IPv4Network

from CybORG.Simulator.Actions import (Action, DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, 
        PrivilegeEscalate, Impact)
from CybORG.Agents.Utils.ObservationWrapper import ObservationWrapper

@dataclass
class RedAgentBelief():
    def __init__(self):
        self.last_action = None
        self.hosts = {}
        self.subnets = {}

    @property
    def unscanned_subnets(self) -> list:
        return [s.subnet for s in self.subnets.values() if not s.scanned]

    def update(self, observation: dict, action: Tuple[Action, None]=None) -> None:
        self.last_action = action
        
        obs = ObservationWrapper(observation)
        self._process_last_action_effect(obs)
        self._extract_data(obs)


    def _process_last_action_effect(self, obs: ObservationWrapper) -> None:
        if self.last_action is None:
            return
        elif self.last_action.name == 'Sleep':
            return
        elif self.last_action.name == 'DiscoverRemoteSystems': 
            self._process_subnet_scan(obs)
        elif self.last_action.name == 'DiscoverNetworkServices': 
            self._process_port_scan(obs)
        elif self.last_action.name == 'ExploitRemoteService': 
            self._process_exploit(obs)
        elif self.last_action.name == 'PrivilegeEscalate': 
            self._process_privilege_escalation(obs)
        elif self.last_action.name == 'Impact':
            self._process_impact(obs)
        else:
            raise NotImplementedError

    def _process_subnet_scan(self, obs: ObservationWrapper) -> None:
        if obs.success == False:
            raise ValueError('Subnet scan failed. Check subnet is True in action space.')

        target_subnet = str(self.last_action.subnet)
        assert target_subnet in self.subnets

        subnet_belief = self.subnets[target_subnet]
        subnet_belief.scanned = True

    def _process_port_scan(self, obs: ObservationWrapper) -> None:
        if obs.success == True:
            self._advance_killchain_on_last_target(1)
            
    def _process_exploit(self, obs: ObservationWrapper) -> None:
        if obs.success == True:
            self._advance_killchain_on_last_target(2)
        else:
            self._restore_last_target()
            self._last_target_is_defender()

    def _process_privilege_escalation(self, obs: ObservationWrapper) -> None:
        if obs.success == True:
            self._advance_killchain_on_last_target(3)
        else:
            self._restore_last_target()

    def _process_impact(self, obs: ObservationWrapper) -> None:
        target_hostname = self.last_action.hostname
        target_ip = self._get_ip(target_hostname)
        target_host = self.hosts[str(target_ip)]

        if obs.success == False:
            if target_host.is_opserver:
                self._restore_last_target()
        else:
            target_host.is_opserver = True

    def _advance_killchain_on_last_target(self, action_value) -> None:
        if hasattr(self.last_action, 'ip_address'):
            target_ip = self.last_action.ip_address
        elif hasattr(self.last_action, 'hostname'):
            target_ip = self._get_ip(self.last_action.hostname)
        else:
            raise ValueError(f'{self.last_action.name} has no ip or hostname attribute.')

        target_host = self.hosts[str(target_ip)]
        target_status = target_host.status

        if target_status.value < action_value:
            target_host.advance_killchain()

    def _get_ip(self, hostname: str) -> IPv4Address:
        for host in self.hosts.values():
            if host.name == hostname:
                return host.ip
        else:
            raise ValueError(f'RedAgentBelief has no host with name {hostname}')

    def _restore_last_target(self) -> None:
        if hasattr(self.last_action, 'hostname'):
            target_hostname = self.last_action.hostname
            target_ip = self._get_ip(target_hostname)
        else:
            target_ip = self.last_action.ip_address

        target_host = self.hosts[str(target_ip)]
        
        target_host.restore()
    
    def _last_target_is_defender(self) -> None:
        if hasattr(self.last_action, 'hostname'):
            target_hostname = self.last_action.hostname
            target_ip = self._get_ip(target_hostname)
        else:
            target_ip = self.last_action.ip_address

        target_host = self.hosts[str(target_ip)]
        target_host.is_defender = True

    def _extract_data(self, obs: ObservationWrapper) -> None:
        for host in obs.hosts:
            ip = obs.get_ip(host)
            if ip is None:
                continue
            self._process_ip_address(ip)

            subnet = obs.get_subnet(host)
            if subnet is not None:
                self._process_subnet(subnet, ip)

            hostname = obs.get_hostname(host)
            if hostname is not None:
                self._process_hostname(hostname, ip)

            has_root = obs.has_red_access(host, only_root=True)
            if has_root:
                self._add_root(ip)


    def _process_ip_address(self, ip: IPv4Address) -> None:
        if str(ip) in self.hosts:
            return
        
        self.hosts[str(ip)] = HostBelief(ip)

    def _process_subnet(self, subnet: IPv4Network, ip: IPv4Address) -> None:
        host_belief = self.hosts[str(ip)]
        host_belief.subnet = subnet

        if str(subnet) not in self.subnets:
            self.subnets[str(subnet)] = SubnetBelief(subnet)

        subnet_belief = self.subnets[str(subnet)]
        subnet_belief.hosts.add(ip)

    def _process_hostname(self, hostname: str, ip: IPv4Address) -> None:
        host_belief = self.hosts[str(ip)]
        host_belief.name = hostname

    def _add_root(self, ip: IPv4Address):
        self.hosts[str(ip)].status = HostStatus.PRIVILEGED_ACCESS

    def clear(self):
        self.__init__() 


    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        equality_tuple = (
                self.last_action == other.last_action,
                self.hosts == other.hosts,
                self.subnets == other.subnets
                )

        return all(equality_tuple)

    def __repr__(self):
        return 'RedAgentBelief: ' + str(self.__dict__)

class HostStatus(Enum):
    UNDISCOVERED = -1
    DISCOVERED = 0
    SCANNED = 1
    USER_ACCESS = 2
    PRIVILEGED_ACCESS = 3

@dataclass
class HostBelief:
    ip: IPv4Address
    subnet: IPv4Network = None
    name: str = None
    status: HostStatus = HostStatus.DISCOVERED
    is_defender: bool = False
    is_opserver: bool = False

    def advance_killchain(self) -> None:
        new_status = min(self.status.value + 1,3)
        self.status = HostStatus(new_status)

    def restore(self) -> None:
        self.status = HostStatus.SCANNED

    @property
    def next_action(self) -> Action:
        """Returns the action required to progress the kill chain for the selected host"""
        if self.status == HostStatus.UNDISCOVERED:
            raise ValueError(f'{self.name} is undiscovered. No next action.')
        elif self.status == HostStatus.DISCOVERED:
            return DiscoverNetworkServices(ip_address=self.ip, agent='Red', session=0)
        elif self.status == HostStatus.SCANNED:
            return ExploitRemoteService(ip_address=self.ip, agent='Red', session=0)
        elif self.status == HostStatus.USER_ACCESS:
            return PrivilegeEscalate(hostname=self.name, agent='Red', session=0)
        elif self.status == HostStatus.PRIVILEGED_ACCESS:
            return Impact(hostname=self.name, agent='Red', session=0)


@dataclass
class SubnetBelief:
    def __init__(self, subnet: IPv4Network, hosts=set(), scanned=False, has_firewall=False):
        self.subnet = subnet
        self.hosts = hosts
        self.scanned = scanned
        self.has_firewall = has_firewall

    @property
    def next_action(self) -> Action:
        return DiscoverRemoteSystems(self.subnet, agent='Red', session=0)

    def __eq__(self, other) -> bool:
        if not isinstance(other, self.__class__):
            return False

        equality_tuple = (
                self.subnet == other.subnet,
                self.hosts == other.hosts,
                self.scanned == other.scanned,
                )

        return all(equality_tuple)
