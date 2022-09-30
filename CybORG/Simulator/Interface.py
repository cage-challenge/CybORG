# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network

from CybORG.Simulator.Entity import Entity


class Interface(Entity):
    def __init__(self, name: str = None, ip_address: str = None, subnet: str = None):
        super().__init__()
        self.name = name
        self.ip_address = IPv4Address(ip_address)
        # subnet replaced with Subnet object during state initialisation
        if type(subnet) is str:
            subnet = IPv4Network(subnet)
        self.subnet = subnet

    def get_state(self):
        return {"interface_name": self.name, "ip_address": self.ip_address, "subnet": str(self.subnet)}
