# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Entity import Entity
from ipaddress import IPv4Network


class Subnet(Entity):
    def __init__(self, cidr: IPv4Network = None, ip_addresses: list = None, nacls: dict = None, name: str = None):
        super().__init__()
        self.cidr = cidr
        self.ip_addresses = ip_addresses
        self.nacls = nacls
        self.name = name

    def get_state(self): #TODO
        pass

    def contains_ip_address(self, ip_address: str) -> bool:
        # returns true if the specified ip address is in the subnet
        return ip_address in self.cidr

    def __str__(self):
        return str(self.cidr)
