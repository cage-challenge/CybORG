## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.
import hashlib
from copy import deepcopy
from datetime import datetime

from ipaddress import IPv4Network, IPv4Address
from random import randrange
from typing import Optional, List

from CybORG.Shared.Enums import (
        SessionType, OperatingSystemPatch, OperatingSystemKernelVersion,
        OperatingSystemVersion, DecoyType,
        OperatingSystemDistribution, OperatingSystemType
        )

from CybORG.Simulator.Entity import Entity
from CybORG.Simulator.File import File
from CybORG.Simulator.Interface import Interface
from CybORG.Simulator.LocalGroup import LocalGroup
from CybORG.Simulator.MSFServerSession import MSFServerSession
from CybORG.Simulator.Process import Process
from CybORG.Simulator.Session import VelociraptorServer, RedAbstractSession, Session

from CybORG.Simulator.User import User


class Host(Entity):
    """Simulates a host.

    This class simulates the internals of a host, including files, processes and interfaces.
    The methods are used to change the state of the host.
    """

    def __init__(self, system_info: dict, hostname: str = None, users: dict = None,
                 files: list = None, sessions: dict = None, processes: list = None, interfaces: list = None, info: dict = None,
                 services: dict = None):
        super().__init__()
        self.original_services = {}
        self.os_type = OperatingSystemType.parse_string(system_info["OSType"])
        self.distribution = OperatingSystemDistribution.parse_string(system_info["OSDistribution"])
        self.version = OperatingSystemVersion.parse_string(str(system_info["OSVersion"]))
        kernel = None
        if "OSKernelVersion" in system_info:
            kernel = OperatingSystemKernelVersion.parse_string(system_info["OSKernelVersion"])
        self.kernel = kernel
        self.patches = []
        if "Patches" in system_info:
            for patch in system_info["Patches"]:
                self.patches.append(OperatingSystemPatch.parse_string(patch))
        self.hostname = hostname
        self.architecture = system_info["Architecture"]
        self.respond_to_ping = True

        self.users = []
        if users is not None:
            for user_info in users:
                self.users.append(
                    User(username=user_info.get('Username'), groups=user_info.get('Groups'), uid=user_info.get('UID'),
                         password=user_info.get('Password'), bruteforceable=user_info.get('Bruteforceable', False)))

        self.files = []
        if files is not None:
            for file in files:
                self.files.append(File(**file))
        self.original_files = deepcopy(self.files)

        self.sessions = {}
        if sessions is not None:
            for agent_name, session in sessions.items():
                self.add_session(agent=agent_name, **session)
        self.original_sessions = deepcopy(self.sessions)

        self.default_process_info = processes
        self.processes = []
        if processes is not None:
            for process in processes:
                self.processes.append(
                    Process(pid=process.get('PID'), parent_pid=process.get('PPID'), username=process.get("Username"),
                            process_name=process.get('Process Name'), path=process.get('Path'),
                            open_ports=process.get('Connections'), properties=process.get('Properties'),
                            process_version=process.get('Process Version'), # adding process version.
                            process_type=process.get('Process Type')))
        self.original_processes = deepcopy(self.processes)

        self.interfaces = [Interface(name='lo', ip_address="127.0.0.1", subnet="127.0.0.0/8")]
        if interfaces is not None:
            for interface in interfaces:
                interface['name'] = f'eth{len(self.interfaces) - 1}'
                self.interfaces.append(Interface(**interface))

        self.ephemeral_ports = []
        self.services = {}
        if services is not None:
            for service_name, service_info in services.items():
                self.services[service_name] = {'active': service_info.get('active'),
                                          'process': service_info.get('PID')}
        self.info = info if info is not None else {}
        self.events = {'NetworkConnections': [], 'ProcessCreation': []}

    def get_state(self):
        observation = {"os_type": self.os_type, "os_distribution": self.distribution, "os_version": self.version,
                       "os_patches": self.patches, "os_kernel": self.kernel, "hostname": self.hostname,
                       "architecture": self.architecture}
        return observation

    def get_ephemeral_port(self):
        port = randrange(49152, 60000)
        if port in self.ephemeral_ports:
            port = randrange(49152, 60000)
        self.ephemeral_ports.append(port)
        return port

    def add_session(self, username, ident, agent, parent, timeout=0, pid=None, session_type="Shell", name=None, artifacts=None,
            is_escalate_sandbox:bool=False):
        if parent is not None:
            parent_id = parent.ident
        else:
            parent_id = None
        if pid is None:
            pid = self.add_process(name=str(session_type), user=username).pid
        if session_type == 'MetasploitServer':
            new_session = MSFServerSession(host=self.hostname, user=username, ident=ident, agent=agent, process=pid,
                                           timeout=timeout, session_type=session_type, name=name)
        elif session_type == 'RedAbstractSession':
            new_session = RedAbstractSession(host=self.hostname, agent=agent, username=username, ident=ident, pid=pid,
                                             timeout=timeout, session_type=session_type, name=name)
        elif session_type == 'VelociraptorServer':
            new_session = VelociraptorServer(host=self.hostname, agent=agent, username=username, ident=ident, pid=pid,
                                             timeout=timeout, session_type=session_type, name=name, artifacts=artifacts)
        else:
            new_session = Session(host=self.hostname, agent=agent, username=username, ident=ident, pid=pid,
                                  timeout=timeout, parent=parent_id, session_type=session_type, name=name, is_escalate_sandbox=is_escalate_sandbox)

        if parent is not None:
            parent.children[new_session.ident] = new_session
        # TODO revisit the base ssh issue
        # elif new_session.session_type != SessionType.SHELL and new_session.session_type != SessionType.VELOCIRAPTOR_SERVER and new_session.session_type != SessionType.MSF_SERVER:
        #     raise ValueError(f"New Session of type {new_session.session_type.name} requires parent but none has been set")
        if agent not in self.sessions:
            self.sessions[agent] = []
        self.sessions[agent].append(new_session.ident)
        return new_session

    def add_process(self, name: str, user: str, pid: int = None, ppid: int = None, path: str = None,
                    program: str = None, process_type: str = None, version: str = None, open_ports: list = None,
                    decoy_type: DecoyType = DecoyType.NONE, connections=None, properties: Optional[List[str]] = None):
        if pid is None:
            pids = []
            for process in self.processes:
                pids.append(process.pid)
            pid = 0
            while pid == 0 or pid in pids:
                pid = randrange(32768)
        if type(open_ports) is dict:
            open_ports = [open_ports]

        process = Process(pid=pid, process_name=name, parent_pid=ppid, path=path, username=user, program_name=program,
                          process_type=process_type, process_version=version, open_ports=open_ports, decoy_type = decoy_type, properties = properties)
        self.processes.append(process)
        return process

    def add_file(self, name: str, path: str, user: str = None, user_permissions: str = None,
                 group: str = None, group_permissions: int = None, default_permissions: int = None, density=0, signed=False):

        file = File(name=name, path=path, user=self.get_user(user), user_permissions=user_permissions,
                    group=group, group_permissions=group_permissions, default_permissions=default_permissions, density=density, signed=signed)
        self.files.append(file)
        return file

    def add_user(self, username: str, password: str = None, password_hash_type: str = None):
        if self.os_type == OperatingSystemType.LINUX:
            uid_list = [999]
            for user in self.users:
                uid_list.append(user.uid)
            if username in uid_list:
                return None
            uid = max(uid_list) + 1  # Algorithm Tested in Linux: useradd
        elif self.os_type == OperatingSystemType.WINDOWS:
            uid_list = []
            for user in self.users:
                uid_list.append(user.username)
            if username in uid_list:
                return None
            uid = None
        else:
            raise NotImplementedError('Only Windows or Linux OS are Implemented')

        if password_hash_type is None:
            if self.os_type == OperatingSystemType.LINUX:
                password_hash_type = 'sha512'
            elif self.os_type == OperatingSystemType.WINDOWS:
                password_hash_type = 'NTLM'

        if password_hash_type == 'sha512':
            password_hash = hashlib.sha512(bytes(password, 'utf-8')).hexdigest()
        elif password_hash_type == 'NTLM':
            password_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        else:
            raise NotImplementedError('Only sha512 and NTLM hashes have been implemented')

        new_user = User(username=username, uid=uid, password=password, password_hash=password_hash,
                        password_hash_type=password_hash_type, groups=None, logged_in=False)

        self.users.append(new_user)
        return new_user

    def get_user(self, username):
        for user in self.users:
            if username == user.username:
                return user
        return None

    def get_interface(self, name=None, cidr=None, ip_address=None, subnet_name=None):
        """A method to get an interface with a selected name, subnet, or IP Address"""
        for interface in self.interfaces:
            if name is not None:
                if interface.name == name:
                    return interface
            if cidr is not None:
                if interface.subnet == cidr:
                    return interface
            if ip_address is not None:
                if interface.ip_address == ip_address:
                    return interface

    def get_process(self, pid):
        for process in self.processes:
            if process.pid == pid:
                return process

    def get_file(self, name, path=None):
        for file in self.files:
            if file.name == name and (not path or file.path == path):
                return file

    def disable_user(self, username):
        user = self.get_user(username)
        if user is not None:
            return user.disable_user()
        else:
            return False

    def remove_user_group(self, user, group):
        user = self.get_user(user)
        if user is not None:
            return True
        return False

    def start_service(self, service_name: str):
        """starts a stopped service, no effect if service already started"""
        if service_name in self.services:
            if self.services[service_name]['process'] not in self.processes:
                self.services[service_name]['active'] = True
                p = self.services[service_name]['process']
                p.pid = None
                process = self.add_process(**p.__dict__)
                self.services[service_name]['process'] = process
                return process, self.services[service_name]['session']
            else:
                return self.services[service_name]['process'], self.services[service_name]['session']

    def stop_service(self, service_name: str):
        """stops a started service, no effect if service already stopped"""
        if service_name in self.services:
            if self.services[service_name]['active']:
                self.services[service_name]['active'] = False
                return self.services[service_name]['process']

    def add_service(self, service_name: str, process: int, session=None):
        """adds a service, and starts it"""
        if service_name not in self.services:
            self.services[service_name] = {'process': process, 'active': True,
                                           'session': session}  # consider turning into a class
        # TODO debug duplicate service error
        # else:
        #     raise ValueError(f'Service {service_name} already on host {self.hostname}')

    def create_backup(self):

        self.original_files = []
        if self.files is not None:
            for file in self.files:
                self.original_files.append(File(**file.get_state()[0]))

        self.original_sessions = {}
        if self.sessions is not None:
            for agent_name, sessions in self.sessions.items():
                if agent_name not in self.original_sessions:
                    self.original_sessions[agent_name] = []
                self.original_sessions[agent_name] += sessions

        self.original_processes = []
        if self.processes is not None:
            for process in self.processes:
                temp = None
                for p in process.get_state():
                    if temp is None:
                        open_port = {}
                        if 'local_port' in p:
                            open_port['local_port'] = p.pop('local_port')
                        if 'remote_port' in p:
                            open_port['remote_port'] = p.pop('remote_port')
                        if 'local_address' in p:
                            open_port['local_address'] = p.pop('local_address')
                        if 'remote_address' in p:
                            open_port['remote_address'] = p.pop('remote_address')
                        if 'transport_protocol' in p:
                            open_port['transport_protocol'] = p.pop('transport_protocol')
                        if len(process.properties) > 0:
                            p['properties'] = process.properties

                        temp = p
                        temp['open_ports'] = []
                        if len(open_port) > 0:
                            temp['open_ports'].append(open_port)
                    else:
                        open_port = {}
                        if 'local_port' in p:
                            open_port['local_port'] = p['local_port']
                        if 'remote_port' in p:
                            open_port['remote_port'] = p['remote_port']
                        if 'local_address' in p:
                            open_port['local_address'] = p['local_address']
                        if 'remote_address' in p:
                            open_port['remote_address'] = p['remote_address']
                        if 'transport_protocol' in p:
                            open_port['transport_protocol'] = p['transport_protocol']
                        if len(open_port) > 0:
                            temp['open_ports'].append(open_port)
                self.original_processes.append(Process(**temp))

        self.ephemeral_ports = []
        self.original_services = {}
        if self.services is not None:
            for service_name, service_info in self.services.items():
                self.original_services[service_name] = {'active': service_info.get('active'),
                                               'process': service_info.get('PID')}

    def restore(self):
        self.events = {'NetworkConnections': [], 'ProcessCreation': []}
        self.files = []
        if self.original_files is not None:
            for file in self.original_files:
                self.files.append(File(**file.get_state()))

        self.sessions = {}
        if self.original_sessions is not None:
            for agent_name, sessions in self.original_sessions.items():
                if agent_name not in self.sessions:
                    self.sessions[agent_name] = []
                self.sessions[agent_name] += sessions

        self.processes = []
        if self.original_processes is not None:
            for process in self.original_processes:
                temp = None
                for p in process.get_state():
                    if temp is None:
                        open_port = {}
                        if 'local_port' in p:
                            open_port['local_port'] = p.pop('local_port')
                        if 'remote_port' in p:
                            open_port['remote_port'] = p.pop('remote_port')
                        if 'local_address' in p:
                            open_port['local_address'] = p.pop('local_address')
                        if 'remote_address' in p:
                            open_port['remote_address'] = p.pop('remote_address')
                        if 'transport_protocol' in p:
                            open_port['transport_protocol'] = p.pop('transport_protocol')
                        if len(process.properties) > 0:
                            p['properties'] = process.properties
                        temp = p
                        temp['open_ports'] = []
                        if len(open_port) > 0:
                            temp['open_ports'].append(open_port)
                    else:
                        open_port = {}
                        if 'local_port' in p:
                            open_port['local_port'] = p['local_port']
                        if 'remote_port' in p:
                            open_port['remote_port'] = p['remote_port']
                        if 'local_address' in p:
                            open_port['local_address'] = p['local_address']
                        if 'remote_address' in p:
                            open_port['remote_address'] = p['remote_address']
                        if 'transport_protocol' in p:
                            open_port['transport_protocol'] = p['transport_protocol']
                        if len(open_port) > 0:
                            temp['open_ports'].append(open_port)
                self.processes.append(Process(**temp))

        self.ephemeral_ports = []
        self.services = {}
        if self.original_services is not None:
            for service_name, service_info in self.original_services.items():
                self.services[service_name] = {'active': service_info.get('active'),
                                                        'process': service_info.get('PID')}

    def __str__(self):
        return f'{self.hostname}'
