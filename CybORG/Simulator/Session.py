## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.
from ipaddress import IPv4Address

from CybORG.Shared.Enums import SessionType, OperatingSystemType
from CybORG.Simulator.Entity import Entity


class Session(Entity):

    def __init__(self, ident: int, host: str, username: str, agent: str,
                 pid: int, timeout: int = 0, session_type: str = 'shell', 
                 active: bool = True, parent=None, name=None,
                 is_escalate_sandbox: bool = False):
        super().__init__()
        self.ident = ident
        self.host = host
        self.username = username
        self.agent = agent
        self.timeout = timeout
        self.pid = pid
        self.parent = parent
        self.session_type = SessionType.parse_string(session_type) if type(session_type) is str else session_type
        self.active = active
        self.children = {}
        self.name = name
        self.is_escalate_sandbox = is_escalate_sandbox

    def get_state(self):
        return {"username": self.username, "session_id": self.ident, "timeout": self.timeout,
                "pid": self.pid, "session_type": self.session_type, "agent": self.agent}

    def set_orphan(self):
        self.active = False
        self.parent = None

    def dead_child(self, child_id: int):
        self.children.pop(child_id)


class RedAbstractSession(Session):
    # a session that remembers previously seen information that can be used by actions
    def __init__(self, ident: int, host: str, username: str, agent: str,
                 pid: int, timeout: int = 0, session_type: str = 'shell', active: bool = True, parent=None, name=None):
        super().__init__(ident, host, username, agent, pid, timeout, session_type, active , parent, name)
        self.ports = {} # a mapping of IP Addresses to previously seen open ports
        self.operating_system = {} # a mapping of hostnames to os types
        self.ot_service = None

    def addport(self, ip_address: IPv4Address, port: int):
        if ip_address in self.ports:
            self.ports[ip_address].append(port)
        else:
            self.ports[ip_address] = [port]

    def clearports(self, ip_address: IPv4Address):
            self.ports[ip_address] = []

    def addos(self, hostname: str, os: OperatingSystemType):
        self.operating_system[hostname] = os

class GreenAbstractSession(Session):
    # Currently a clone of RedAbstractSession
    # a session that remembers previously seen information that can be used by actions
    def __init__(self, ident: int, host: str, username: str, agent: str,
                 pid: int, timeout: int = 0, session_type: str = 'shell', active: bool = True, parent=None, name=None):
        super().__init__(ident, host, username, agent, pid, timeout, session_type, active , parent, name)
        self.ports = {} # a mapping of IP Addresses to previously seen open ports
        self.operating_system = {} # a mapping of hostnames to os types
        self.ot_service = None

    def addport(self, ip_address: IPv4Address, port: int):
        if ip_address in self.ports:
            self.ports[ip_address].append(port)
        else:
            self.ports[ip_address] = [port]

    def addos(self, hostname: str, os: OperatingSystemType):
        self.operating_system[hostname] = os

class VelociraptorServer(Session):
    # a session that remembers previously seen information that can be used by actions
    def __init__(self, ident: int, host: str, username: str, agent: str,
                 pid: int, timeout: int = 0, session_type: str = 'shell', active: bool = True, parent=None, name=None,
                 artifacts=None):
        super().__init__(ident, host, username, agent, pid, timeout, session_type, active , parent, name)
        self.artifacts = [] if artifacts is None else artifacts  # a list of artifacts that the velociraptor collects
        self.sus_pids = {}
        self.sus_files = {}

    def add_sus_pids(self, hostname: str, pid: int):
        if hostname in self.sus_pids:
            self.sus_pids[hostname].append(pid)
        else:
            self.sus_pids[hostname] = [pid]
