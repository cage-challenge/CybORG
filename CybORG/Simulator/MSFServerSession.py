# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Session import Session
from CybORG.Simulator.Process import Process


class MSFServerSession(Session):

    def __init__(self, ident: str, host: str, user: str, agent: str,
                 process: Process, timeout: int = 0, session_type: str = 'msf server', name=None):
        super().__init__(ident, host, user, agent,
                 process, timeout, session_type, name=name)
        self.routes = {}  # routes have the structure sessionid: subnet

    def dead_child(self, child_id: int):
        super().dead_child(child_id)
        if child_id in self.routes:
            self.routes.pop(child_id)
