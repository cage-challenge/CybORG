from .HeuristicRed import HeuristicRed
from CybORG.Shared.Actions.Action import Sleep


class DebuggingAgent(HeuristicRed):
    def __init__(self, ip_list:list,session=0):
        super().__init__(session=session)
        self.ip_list = ip_list
        self.position = 0
        self.active_ip = self.ip_list[self.position]

    def _choose_ip(self):
        ip = self.active_ip
        status = self.ip_status[ip]
        if status >= 3:
            self.position += 1 if self.position < len(self.ip_list) - 1 else 0
            ip = self.active_ip = self.ip_list[self.position]

        assert ip in self.ip_status
        return ip
