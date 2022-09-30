# Copyright DST Group. Licensed under the MIT license.
import copy

from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import FileType, SessionType, FileVersion, OperatingSystemType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.File import File
from CybORG.Simulator.Session import Session
from CybORG.Simulator.State import State


class ShellPrivilegeEscalation(ShellAction):
    def __init__(self, attacker_session: int, agent, target_session: int):
        super().__init__(attacker_session, agent)
        self.target_session = target_session
        self.obs = Observation()

    def sim_execute(self, state: State):
        pass

    def run_web_server(self, session: Session):
        for file in session.host.files:
            if file.file_type == FileType.PYTHON:
                session.host.add_process(name="python", ppid=session.process.pid, user=session.user, open_ports={"Port": 8080, "Application Protocol": "HTTP", "Address": "broadcast"}, process_type="webserver", version="python SimpleHTTPServer")
                self.obs.add_process(hostid="hostid0", local_address="0.0.0.0", local_port=8080, status="open", process_type="webserver", process_version="python SimpleHTTPServer")
                break

    def copy_files_to_webserver(self, session, file):
        if file.check_readable(session.user) and session.host.os_type == OperatingSystemType.LINUX:
            new_file = copy.deepcopy(file)
            new_file.path = "/tmp/webserver/"
            session.host.files.append(new_file)
            self.obs.add_file_info(hostid="hostid0", name=file.name, path=file.path, file_type=file.file_type)
            self.obs.add_file_info(hostid="hostid0", name=new_file.name, path=new_file.path, file_type=new_file.file_type)
            self.obs.add_system_info(hostid="hostid0", os_type=OperatingSystemType.LINUX)
            return new_file

    def download_file(self, session, file, ip_address, from_ip_address):
        if session.session_type == SessionType.SHELL:
            self.obs.add_interface_info(hostid="hostid1", ip_address=from_ip_address)
            new_file = copy.deepcopy(file)
            new_file.path = "/tmp/"
            new_file.user = session.user
            new_file.group = session.user.groups[0].name
            session.host.files.append(new_file)
            self.obs.add_file_info(hostid="hostid1", name=new_file.name, path=new_file.path, file_type=new_file.file_type)
            return new_file

    def compile_file(self, session, code_file: File):
        # find gcc to compile files
        for file in session.host.files:
            if file.file_type == FileType.GCC:
                if file.check_executable(session.user):
                    if code_file.check_readable(session.user):
                        if code_file.file_type == FileType.DirtyCowCode and file.version == FileVersion.U4_2_4_1 and session.host.os_type == OperatingSystemType.LINUX:
                            exe_file = copy.deepcopy(code_file)
                            exe_file.file_type = FileType.DirtyCowExe
                            exe_file.name = "40839"
                            session.host.files.append(exe_file)
                            self.obs.add_file_info(hostid="hostid1", name=exe_file.name, path=exe_file.path,
                                                   file_type=exe_file.file_type)
                            self.obs.add_system_info(hostid="hostid1", os_type=OperatingSystemType.LINUX)
                            return exe_file
                        elif code_file.file_type == FileType.UDEV141CODE and session.host.os_type == OperatingSystemType.LINUX and file.version == FileVersion.U4_2_4_1:
                            exe_file = copy.deepcopy(code_file)
                            exe_file.file_type = FileType.UDEV141EXE
                            exe_file.name = "8572"
                            session.host.files.append(exe_file)
                            self.obs.add_file_info(hostid="hostid1", name=exe_file.name, path=exe_file.path,
                                                   file_type=exe_file.file_type)
                            self.obs.add_system_info(hostid="hostid1", os_type=OperatingSystemType.LINUX)
                            return exe_file

    def switch_user(self, session, username, password):
        for user in session.host.users:
            if user.username == username:
                if user.password == password:
                    session.user = user
                    self.obs.add_session_info(hostid="hostid1", session_id=session.ident, timeout=0, username=username, session_type=session.session_type, agent=self.agent)
                    break
