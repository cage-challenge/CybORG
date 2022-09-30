# Copyright DST Group. Licensed under the MIT license.
import CybORG.Shared.Enums as CyEnums
from CybORG.Shared.Enums import OperatingSystemType as ost
from CybORG.Shared.Actions.VelociraptorActionsFolder.VelociraptorArtifactAction import VelociraptorArtifactAction
from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation


class KillProcessPID(VelociraptorArtifactAction):
    """Kill a process with the given PID"""

    def __init__(self, session: int, agent: str, hostname: str, process: int, ostype: ost):
        self.pid = process
        if ostype == CyEnums.OperatingSystemType.WINDOWS:

            command = f"taskkill!/f!/pid!{process}"

        else:

            command = f"/bin/kill!-9!{process}"

        self.debug(f"In KillProcessPID with command={command}")

        super().__init__(session=session,
                         hostname=hostname,
                         artifact='Custom.Cyborg.Generic.RunWindowsClientCommand',
                         env=dict(command=command),
                         agent=agent,
                         flow_completion_wait_limit=90
                         #                         tag=agent
                         )
        # self.agent = agent
        # self.hostname = hostname
        # self.pid = process
        # self.parameters['artifactname'] = ["Custom.CybORG.Generic.RunWindowsClientCommand",
        #                                    "Custom.Cyborg.Generic.RunLinuxClientCommand"]

        # # TBD: Change to a single artifact as Custom.CybORG.Generic.RunWindowsClientCommand
        # # and Custom.Cyborg.Generic.RunLinuxClientCommand are identical and will just be
        # # passed a different command string
        #
        # self.query = (
        #     'select collect_client('
        #     'client_id="<host_id>", '
        #     'artifacts=["Custom.Cyborg.Generic.RunWindowsClientCommand", '
        #     '"Custom.Cyborg.Generic.RunLinuxClientCommand"], '
        #     'env=dict(command="taskkill!/f!/pid!<process>", '
        #     'command="kill!-9!<process>")) '
        #     'FROM scope()'
        # )
        # self.source_query = (
        #     "select * from chain("
        #     "a={select * from source("
        #     "flow_id='<flowid>', "
        #     "client_id='<host_id>', "
        #     "artifact='Custom.Cyborg.Generic.RunWindowsClientCommand')}, "
        #     "b={select * from source("
        #     "flow_id='<flowid>', "
        #     "client_id='<host_id>', "
        #     "artifact='Custom.Cybprg.Generic.RunLinuxClientCommand')})"
        # )

    def sim_execute(self, state):
        raise NotImplementedError

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()
        self.debug(f"client_id={client_id} results={results}")
        if results[0]['Stderr'] == '':# or results[1]['stderr'] == '':
            obs.add_raw_obs(results)
            obs.set_success(True)
        else:
            obs.set_success(False)
        return obs

    def __str__(self):
        return super(KillProcessPID, self).__str__() + f", PID: {self.pid}"
