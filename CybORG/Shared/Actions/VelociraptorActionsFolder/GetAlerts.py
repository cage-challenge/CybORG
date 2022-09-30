# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class GetAlerts(VelociraptorAction):
    """Get latest alerts.

    This action will poll server for any new alerts (since last poll)
    for artifacts monitored by the target session (as defined in scenario
    file).
    """

    def __init__(self, session: int, agent: str):
        super().__init__(session=session,
                         query_type=QueryType.SYNC,
                         agent = agent
                         )

    def emu_execute(self,
                    session_handler,
                    *args,
                    **kwargs):
        vel_controller = session_handler.controller
        obs = Observation()
        obs.set_success(True)
        obs = vel_controller.get_latest_alerts(obs)
        return obs

    def parse(self, results: dict) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()
        obs.set_success(True)

        if "message" not in results \
           or "A new process has been created." not in results["message"]:
            return obs

        # Process creation event case:
        event_data = results['event_data']
        obs.add_system_info(
            hostid='0',
            hostname=event_data['SubjectDomainName']
        )

        path = event_data['NewProcessName']
        name = path
        if '/' in path:
            path = path.rsplit('/', 1)[0] + '/'
            name = name.rsplit('/', 1)[1]
        elif '\\' in path:
            path = path.rsplit('\\', 1)[0] + '\\'
            name = name.rsplit('\\', 1)[1]

        obs.add_process(hostid='0', pid=event_data['ProcessId'])
        obs.add_process(
            hostid='0',
            pid=event_data['NewProcessId'],
            parent_pid=event_data['ProcessId'],
            process_name=name,
            username=event_data['SubjectUserName'],
            path=path
        )

        return obs
