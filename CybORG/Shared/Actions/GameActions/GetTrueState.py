# Copyright DST Group. Licensed under the MIT license.
import re
from ipaddress import IPv4Network, IPv4Address

from CybORG.Shared import Observation, CybORGLogger

from .GameAction import GameAction


class GetTrueState(GameAction, CybORGLogger):
    """Get true state of game. """
    def __init__(self, info):
        self.info = info

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        agent_sessions = None
        if self.info is not None:
            obs = Observation()

            for host, data in self.info.items():

                # get systeminfo
                self._log_debug(f"{host}: {data}")
                if "Sessions" in data:

                    if data["Sessions"] == 'All':
                        for agent_name, agent_sessions in game_controller._agents.items():

                            for session in agent_sessions.get_sessions():

                                hostid = session.pop('hostid')
                                try:
                                    hostid = game_controller.network.ip_hostname_map[IPv4Address(hostid)]
                                except:
                                    pass
                                if hostid == host:
                                    obs.add_session_info(hostid=hostid, **session)
                    else:
                        agent_name = data["Sessions"]
                        if agent_sessions is None:
                            agent_sessions = game_controller._agents[agent_name].get_sessions()

                        for session in agent_sessions:

                            if session['hostid'] == host:
                                obs.add_session_info(**session)
                if "System info" in data:
                    # game_controller._log_debug(f'Getting System info for {host}')
                    result = game_controller.execute_ssh_command('systeminfo /FO csv /NH', host)
                    if result == '' or 'command not found' in result or 'Invalid command' in result:
                        # likely fail due to wrong OS
                        result = game_controller.execute_ssh_command('uname -s && uname -m && lsb_release -i && lsb_release -r && hostname', host)
                        result = result.split('\n')
                        # self._log_debug(result)
                        obs.add_system_info(hostid=host, hostname=result[4], architecture=result[1], os_type=result[0], os_distribution=result[2].split(':\t')[1], os_version=result[3].split(':\t')[1])
                    else:
                        result = result.split(',')
                        obs.add_system_info(hostid=host, OSType=result[1], OSDistribution=result[1], OSVersion=result[2], architecture=result[15].split('-')[0][1:])
                        # game_controller._log_debug(f"System info: {result}")
                # get processes
                if "Processes" in data:
                    # data[processes] = {'All'}|{['PID','PPID','User','Port']}
                    # the elements in Processes determines what data is required from the processes
                    procs_to_ignore = ['-']
                    # game_controller._log_debug(f'Getting Process info for {host}')
                    if 'All' in data['Processes'] or 'PID' in data['Processes']:
                        # try tasklist command for windows
                        result = game_controller.execute_ssh_command('tasklist /FO csv', host)

                        if result == '' or 'command not found' in result or 'Invalid command' in result:
                            # if failed then try linux command
                            result = game_controller.execute_ssh_command("ps -e -o user,pid,ppid,command | awk '{print $1,$2,$3,$4}'", host)
                            result = result.split('\n')

                            for proc in result:
                                if "Image Name" in proc or 'USER' in proc:
                                    continue
                                p = proc.split(' ')
                                if len(p) == 4:
                                    if p[0] != 'ec2-user' and p[0] != 'ubuntu':
                                        if '/' in p[3] and '[' not in p[3]:
                                            path, name = p[3][:p[3].rfind('/')], p[3][p[3].rfind('/')+1:]
                                        else:
                                            name = p[3]
                                            path = None
                                        obs.add_process(hostid=host, pid=int(p[1]), parent_pid=int(p[2]), process_name=name, path=path, username=p[0])
                                    else:
                                        procs_to_ignore.append(p[1])
                        else:
                            result = result.split('\n')[1:]
                            # game_controller._log_debug(f"Process info: {result}")
                            for r in result:
                                r = r.replace('"','').split(',')
                                if len(r)>1:
                                    obs.add_process(hostid=host, process_name=r[0], pid=r[1])
                            if 'All' in data['Processes'] or 'PPID' in data['Processes']:
                                result = game_controller.execute_ssh_command("wmic process get processid,parentprocessid,name,executablepath /format:csv", host)
                                result = result.split('\n')[2:]
                                # game_controller._log_debug(f"Process info: {result}")
                                ssh_command = ''
                                if 'All' in data['Processes'] or 'User' in data['Processes']:
                                    for r in result:
                                        r = r.replace('"','').split(',')
                                        if len(r) > 4:
                                            path = '\\'.join(r[1].split('\\')[:-1])
                                            ssh_command += f"""wmic process where "name='{r[2]}'" call GetOwner;"""

                                    result2 = game_controller.execute_ssh_command(ssh_command, host)
                                    count = 0
                                    # self._log_debug(f'results2: {result2[:2000]}')
                                    r2 = result2.split('{')[1:]
                                    for r in result:
                                        r = r.replace('"', '').split(',')
                                        if len(r) > 4:
                                            path = '\\'.join(r[1].split('\\')[:-1])
                                            if 'User = ' in r2[count]:
                                                # self._log_debug(f'r2: {r2[count]}')
                                                obs.add_process(hostid=host, path=path if path != '' else None, process_name=r[2], pid=r[3], parent_pid=r[4], username=r2[count].split('User = ')[1].split('"')[1])
                                            else:
                                                obs.add_process(hostid=host, path=path if path != '' else None, process_name=r[2], pid=r[3], parent_pid=r[4])
                                            count += 1

                                else:
                                    for r in result:
                                        r = r.replace('"', '').split(',')
                                        path = '\\'.join(r[1].split('\\')[:-1])
                                        if len(r) > 4:
                                            obs.add_process(hostid=host, path=path if path != '' else None, process_name=r[2], pid=r[3], parent_pid=r[4])

                    if 'All' in data['Processes'] or 'Port' in data['Processes']:
                        result = game_controller.execute_ssh_command("sudo netstat -npl4 | sed 's/LISTEN/ /g' | awk '{print $1,$4,$6}'", host)
                        if result == '' or 'command not found' in result or 'Invalid command' in result:
                            #linux command failed so try windows command
                            result2 = game_controller.execute_ssh_command(f"netstat -ano", host)
                            for line in result2.split('\n'):
                                l = re.sub(' +', ' ', line)
                                l = l.split(' ')
                                # self._log_debug(list(enumerate(l)))
                                if len(l) > 5 and l[4] == 'LISTENING':
                                    lp = int(l[2].split(':')[-1])
                                    la = ''.join(l[2].split(':')[:-1])
                                    ls = ''.join(l[3].split(':')[:-1])
                                    # self._log_debug(la)
                                    if ls == '0.0.0.0':
                                        if la == '127.0.0.1':
                                            obs.add_process(hostid=host, pid=int(l[5]), local_port=lp, local_address=la)
                                        else:
                                            obs.add_process(hostid=host, pid=int(l[5]), local_port=lp, local_address=ls)
                        else:
                            #linux command worked
                            for conn in result.split('\n')[2:]:
                                c = conn.split(' ')
                                if len(c) == 3 and '/' in c[2] and ':' in c[1]:
                                    pid = c[2].split('/')[0]
                                    if pid not in procs_to_ignore:
                                        obs.add_process(hostid=host, pid=int(pid), transport_protocol=c[0], local_address=c[1].split(':')[0], local_port=c[1].split(':')[1])

                # get files
                if "Files" in data:
                    result = ''  # game_controller.execute_ssh_command('dir', host)
                    if result == '' or 'command not found' in result or 'Invalid command' in result:
                        # likely fail due to wrong OS
                        result = game_controller.execute_ssh_command('ls', host)
                    # game_controller._log_debug(f"File info: {result}")
                # get users
                if "User info" in data:
                    # game_controller._log_debug(f'Getting User info for {host}')

                    result = game_controller.execute_ssh_command('wmic useraccount get name,sid /format:csv', host)
                    # game_controller._log_debug(f'result: {result}')
                    if result == '' or 'command not found' in result or 'Invalid command' in result:
                        # likely fail due to wrong OS
                        result = game_controller.execute_ssh_command('cat /etc/passwd', host)
                        for r in result.split('\n'):
                            r = r.split(':')
                            if len(r) >= 4:
                                obs.add_user_info(hostid=host, username=r[0], uid=int(r[2]), gid=int(r[3]))
                        result = game_controller.execute_ssh_command('cat /etc/group', host)
                        for r in result.split('\n'):
                            r = r.split(':')
                            if len(r) == 4:
                                obs.add_user_info(hostid=host, group_name=r[0], gid=int(r[2]))
                                for u in r[3].split(','):
                                    if u != '':
                                        obs.add_user_info(hostid=host, group_name=r[0], gid=int(r[2]), username=u)
                    # game_controller._log_debug(f"User info: {result}")
                    else:
                        for r in result.split('\n')[2:]:
                            r = r.split(',')
                            if len(r) > 2:
                                obs.add_user_info(hostid=host, username=r[1], uid=r[2])
                        # game_controller._log_debug(f"User info: {result}")

                if "Interfaces" in data:
                    # game_controller._log_debug(f'Getting Interface info for {host}')

                    result = game_controller.execute_ssh_command('ip a', host)
                    # game_controller._log_debug(f'ip a on {host}: {result}')
                    if 'command not found' in result:
                        result = game_controller.execute_ssh_command('ipconfig', host)
                        # game_controller._log_debug(f"Interface: {result}")
                        interfaces = result.split('adapter')[1:]
                        for i in interfaces:
                            ip = None
                            mask = None
                            for line in i.split('\n'):
                                if 'IPv4 Address' in line and ': ' in line:
                                    ip = line.split(': ')[1]
                                if 'Subnet Mask' in line and ': ' in line:
                                    mask = line.split(': ')[1]
                            if ip is not None and mask is not None:
                                obs.add_interface_info(hostid=host,
                                                       ip_address=ip,
                                                       subnet=IPv4Network(f'{ip}/{mask}', strict=False))
                    else:
                        for line in result.split('\n'):
                            if 'inet ' in line:
                                l = re.sub(' +', ' ', line).split(' ')
                                if len(l) > 6:
                                    # game_controller._log_debug(f'hostid={host}, interface_name={l[8]}, ip_address={l[2].split("/")[0]}, subnet={IPv4Network(l[2], strict=False)}')
                                    obs.add_interface_info(hostid=host, interface_name=l[8],
                                                           ip_address=l[2].split("/")[0],
                                                           subnet=IPv4Network(l[2], strict=False))

                                else:
                                    # game_controller._log_debug(f'hostid={host}, interface_name={l[5]}, ip_address={l[2].split("/")[0]}, subnet={IPv4Network(l[2], strict=False)}')
                                    obs.add_interface_info(hostid=host, interface_name=l[5],
                                                           ip_address=l[2].split("/")[0],
                                                           subnet=IPv4Network(l[2], strict=False))


            return obs
        return game_controller.get_true_state(self.info)
