## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.
import copy
from ipaddress import IPv4Address
from typing import List, Optional

from CybORG.Shared.Enums import (ProcessType, ProcessVersion,
        TransportProtocol, DecoyType)
from CybORG.Simulator.Entity import Entity
from CybORG.Simulator.User import User


class Process(Entity):
    def __init__(self, process_name: str, pid: int, parent_pid: int, username: str, program_name: str = None,
                 path: str = None, open_ports: list = None, process_type: str = None, process_version: str = None,
                 decoy_type: DecoyType = DecoyType.NONE, properties: List[str] = None):
        """
        :param process_name: name of process
        :param pid: id of process
        :param parent_pid: id of parent of process
        :param program_name: program the process is running
        :param username: the user runnning the process
        :param path: the path of the program the process is running
        :param open_ports: listening ports of structure [{Port: int, Address: str, Application Protocol: str}, ...]
        :param process_type: the type of process
        :param process_version: the version of the process
        :param decoy_type: which red actions are prevented despite appearing vulnerable
        :param properties: properties of the process to specify configuration details such as RFI presence
        """
        super().__init__()
        self.name = process_name
        self.pid = pid
        self.ppid = parent_pid
        self.program = program_name
        self.user = username
        self.path = path
        self.open_ports = open_ports
        self.decoy_type = decoy_type
        self.connections = []  # Connections has the structure [{local_port, local_address, remote_port, Remote Address, Application Protocol}]
        if properties is None:
            self.properties = []
        else:
            self.properties = properties
        if open_ports is not None:
            for port_dict in open_ports:
                interface = port_dict['local_address']
                if interface == 'broadcast':
                    interface = IPv4Address('0.0.0.0')
                elif interface == 'local':
                    interface = IPv4Address('127.0.0.1')
                else:
                    interface = IPv4Address(interface)
                transport_protocol = port_dict.get("transport_protocol", 'UNKNOWN')
                if type(transport_protocol) is not TransportProtocol:
                    transport_protocol = TransportProtocol.parse_string(transport_protocol)
                new_connection = {'local_port': port_dict['local_port'], 'local_address': interface,
                                  'transport_protocol': transport_protocol}

                self.connections.append(new_connection)

        self.process_type = None
        if process_type is not None:
            if type(process_type) is str:
                self.process_type = ProcessType.parse_string(process_type)
            else:
                self.process_type = process_type
        elif process_name is not None:
            self.process_type = ProcessType.parse_string(process_name)

        if process_version is not None:
            self.version = ProcessVersion.parse_string(process_version)
        else:
            self.version = None

    def get_state(self):
        observations = []
        for connections_dict in self.connections:
            obs = {"pid": self.pid, "parent_pid": self.ppid, "process_name": self.name, "program_name": self.program,
                "path": self.path, "process_type": self.process_type,
                   "process_version": self.version, "local_port": connections_dict['local_port'],
                   "local_address": connections_dict["local_address"]}
            if "remote_port" in connections_dict:
                obs["remote_port"] = connections_dict["remote_port"]
            if "remote_address" in connections_dict:
                obs["remote_address"] = connections_dict["remote_address"]
            if "transport_protocol" in connections_dict:
                obs["transport_protocol"] = connections_dict["transport_protocol"]
            if self.user is not None:
                obs["username"] = self.user
            observations.append(obs)
        if not observations:
            obs = {"pid": self.pid,
                   "parent_pid": self.ppid,
                   "process_name": self.name,
                   "program_name": self.program,
                   "path": self.path,
                   "process_type": self.process_type,
                   "process_version": self.version,
                   'username': self.user}
            observations.append(obs)
        return observations

    def __str__(self):
        return f'{self.name}: {self.pid} <- {self.ppid}'
