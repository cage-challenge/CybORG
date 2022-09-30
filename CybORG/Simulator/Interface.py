# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network

from CybORG.Simulator.Entity import Entity


class Interface(Entity):
    def __init__(self, name: str = None, ip_address: str = None, subnet: str = None, interface_type: str = 'wired', data_links: list = None, max_range: float = 100, swarm=False):
        super().__init__()
        self.name = name
        self.interface_type = interface_type
        self.ip_address = IPv4Address(ip_address)
        # subnet replaced with Subnet object during state initialisation
        if type(subnet) is str:
            subnet = IPv4Network(subnet)
        self.subnet = subnet
        if data_links is None:
            self.data_links = []
        else:
            self.data_links = data_links
        self.max_range = max_range
        self.blocked_ips = []
        self.swarm = swarm


    def get_state(self):
        return {"interface_name": self.name, "ip_address": self.ip_address, "subnet": self.subnet}
