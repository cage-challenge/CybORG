# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import MSFAction


class MeterpreterAction(MSFAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session=session, agent=agent)
        self.meterpreter_session = target_session

    def __str__(self):
        return super(MeterpreterAction, self).__str__() + f", Meterpreter Session: {self.meterpreter_session}"
