## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.

import pprint
from copy import deepcopy
from datetime import datetime
from typing import List, Union, Optional
from ipaddress import IPv4Network, IPv4Address

import CybORG.Shared.Enums as CyEnums

BROADCAST_ADDRESS = IPv4Address('0.0.0.0')

class Observation:

    def __init__(self, success:bool = None):
        self.data = {"success": CyEnums.TrinaryEnum.UNKNOWN if success == None else CyEnums.TrinaryEnum.parse_bool(success)}
        self.raw = ''

    def get_dict(self):
        return self.data

    def set_success(self, success: Union[bool, CyEnums.TrinaryEnum]):
        if type(success) is bool:
            success = CyEnums.TrinaryEnum.parse_bool(success)
        self.data["success"] = success

    def add_process(self,
                    hostid: str = None,
                    pid: int = None,
                    parent_pid: int = None,
                    process_name: str = None,
                    program_name: str = None,
                    service_name: str = None,
                    username: str = None,
                    path: str = None,
                    local_port: int = None,
                    remote_port: int = None,
                    local_address: Union[str, IPv4Address] = None,
                    remote_address: Union[str, IPv4Address] = None,
                    app_protocol: str = None,
                    transport_protocol: str = None,
                    status: str = None,
                    process_type: str = None,
                    process_version: str = None,
                    vulnerability: str = None,
                    properties: Optional[List[str]] = None,
                    **kwargs):
        if hostid is None:
            hostid = str(len(self.data))
        if hostid not in self.data:
            self.data[hostid] = {"Processes": []}
        elif "Processes" not in self.data[hostid]:
            self.data[hostid]["Processes"] = []

        new_process = {}

        pid = kwargs.get("PID", None) if pid is None else pid
        if pid is not None:
            if type(pid) is not int:
                pid = int(pid)
            if pid < 0:
                raise ValueError
            for old_process in self.data[hostid]["Processes"]:
                if "PID" in old_process and old_process["PID"] == pid:
                    new_process = old_process
                    self.data[hostid]["Processes"].remove(old_process)
                    break
            new_process["PID"] = pid

        if parent_pid is None:
            parent_pid = kwargs.get("PPID", None)
        if parent_pid is not None:
            if type(parent_pid) is not int:
                parent_pid = int(parent_pid)
            new_process["PPID"] = parent_pid

        if process_name is None:
            process_name = kwargs.get("Process Name", None)
        if process_name is not None:
            new_process["Process Name"] = process_name
            if isinstance(process_name, str):
                process_name = CyEnums.ProcessName.parse_string(process_name)
            new_process["Known Process"] = process_name

        if program_name is None:
            program_name = kwargs.get("Program Name", None)
        if program_name is not None:
            if type(program_name) is str:
                program_name = CyEnums.FileType.parse_string(program_name)
            new_process["Program Name"] = program_name

        if service_name is None:
            service_name = kwargs.get("Service Name", None)
        if service_name is not None:
            new_process["Service Name"] = service_name

        if username is None:
            username = kwargs.get("Username", None)
        if username is not None:
            new_process["Username"] = username

        if path is None:
            path = kwargs.get("Path", None)
        if path is not None:
            new_process["Path"] = path
            new_process["Known Path"] = CyEnums.Path.parse_string(path)

        new_connection = {}
        if "Connections" not in new_process:
            new_process["Connections"] = []

        if local_port is None:
            local_port = kwargs.get("local_port", None)
        if local_port is not None:
            new_connection["local_port"] = int(local_port)

        if remote_port is None:
            remote_port = kwargs.get("remote_port", None)
        if remote_port is not None:
            new_connection["remote_port"] = int(remote_port)

        if local_address is None:
            local_address = kwargs.get("local_address", None)
        if local_address is not None:
            if type(local_address) is str:
                local_address = IPv4Address(local_address)
            new_connection["local_address"] = local_address
            self.add_interface_info(hostid=hostid, ip_address=local_address)

        if remote_address is None:
            remote_address = kwargs.get("remote_address", None)
        if remote_address is not None:
            if type(remote_address) is str:
                remote_address = IPv4Address(remote_address)
            new_connection["remote_address"] = remote_address

        if transport_protocol is not None:
            if type(transport_protocol) is str:
                transport_protocol = CyEnums.TransportProtocol.parse_string(transport_protocol)
            new_connection["Transport Protocol"] = transport_protocol

        if app_protocol is None:
            app_protocol = kwargs.get("Application Protocol", None)
        if app_protocol is not None:
            if type(app_protocol) is str:
                app_protocol = CyEnums.AppProtocol.parse_string(app_protocol)
            new_connection["Application Protocol"] = app_protocol

        if status is None:
            status = kwargs.get("Status", None)
        if status is not None:
            if isinstance(status, str):
                status = CyEnums.ProcessState.parse_string(status)
            new_connection["Status"] = status

        if new_connection != {}:
            new_process["Connections"].append(new_connection)
        elif new_process["Connections"] == []:
            new_process.pop("Connections")

        if process_type is None:
            process_type = kwargs.get("Process Type", None)
        if process_type is not None:
            if type(process_type) is str:
                process_type = CyEnums.ProcessType.parse_string(process_type)
            new_process["Process Type"] = process_type

        if process_version is None:
            process_version = kwargs.get("Process Version", None)
        if process_version is not None:
            if type(process_version) is str:
                process_version = CyEnums.ProcessVersion.parse_string(process_version)
            new_process["Process Version"] = process_version

        if properties is None:
            properties = kwargs.get("Properties", None)
        if properties is not None:
            new_process["Properties"] = properties

        if vulnerability is None:
            vulnerability = kwargs.get("Vulnerability", None)
        if vulnerability is not None:
            if "Vulnerability" not in new_process:
                new_process["Vulnerability"] = []
            if type(vulnerability) is str:
                vulnerability = CyEnums.Vulnerability.parse_string(vulnerability)
            new_process["Vulnerability"].append(vulnerability)

        self.data[hostid]["Processes"].append(new_process)

        if self.data[hostid] == {"Processes": [{}]}:
            self.data.pop(hostid)

    def add_system_info(self,
                        hostid: str = None,
                        hostname: str = None,
                        os_type: str = None,
                        os_distribution: str = None,
                        os_version: str = None,
                        os_kernel: str = None,
                        os_patches: list = None,
                        architecture: str = None,
                        local_time: datetime = None,
                        **kwargs):
        if hostid is None:
            hostid = str(len(self.data))
        if hostid not in self.data:
            self.data[hostid] = {"System info": {}}
        elif "System info" not in self.data[hostid]:
            self.data[hostid]["System info"] = {}
        sys_info = self.data[hostid]["System info"]

        if hostname is None:
            hostname = kwargs.get("Hostname", None)
        if hostname is not None:
            sys_info["Hostname"] = hostname

        if os_type is None:
            os_type = kwargs.get("OSType", None)
        if os_type is not None:
            if type(os_type) is str:
                os_type = CyEnums.OperatingSystemType.parse_string(os_type)
            sys_info["OSType"] = os_type

        if os_distribution is None:
            os_distribution = kwargs.get("OSDistribution", None)
        if os_distribution is not None:
            if type(os_distribution) is str:
                os_distribution = CyEnums.OperatingSystemDistribution.parse_string(os_distribution)
            sys_info["OSDistribution"] = os_distribution

        if os_version is None:
            os_version = kwargs.get("OSVersion", None)
        if os_version is not None:
            if type(os_version) is str:
                os_version = CyEnums.OperatingSystemVersion.parse_string(os_version)
            sys_info["OSVersion"] = os_version

        if os_kernel is None:
            os_kernel = kwargs.get("OSKernelVersion", None)
        if os_kernel is not None:
            if type(os_kernel) is str:
                os_kernel = CyEnums.OperatingSystemKernelVersion.parse_string(os_kernel)
            sys_info["OSKernelVersion"] = os_kernel

        if os_patches is None:
            os_patches = kwargs.get("os_patches", None)
        if os_patches is not None:
            for patch in os_patches:
                if type(patch) is str:
                    patch = CyEnums.OperatingSystemPatch.parse_string(patch)
                if "os_patches" in self.data[hostid]["System info"]:
                    sys_info["os_patches"].append(patch)
                else:
                    sys_info["os_patches"] = [patch]

        if architecture is None:
            architecture = kwargs.get("Architecture", None)
        if architecture is not None:
            if isinstance(architecture, str):
                architecture = CyEnums.Architecture.parse_string(architecture)
            sys_info["Architecture"] = architecture

        if local_time is None:
            local_time = kwargs.get("Local Time", None)
        if local_time is not None:
            sys_info["Local Time"] = local_time

    def add_interface_info(self,
                           hostid: str = None,
                           interface_name: str = None,
                           ip_address: Union[str, IPv4Address] = None,
                           subnet: Union[str, IPv4Network] = None,
                           **kwargs):
        if hostid is None:
            hostid = str(len(self.data))
        if hostid not in self.data:
            self.data[hostid] = {"Interface": []}
        elif "Interface" not in self.data[hostid]:
            self.data[hostid]["Interface"] = []

        new_interface = {}

        if interface_name is None:
            interface_name = kwargs.get("Interface Name", None)
        if interface_name is not None:
            for interface in self.data[hostid]["Interface"]:
                if "Interface Name" in interface:
                    if interface["Interface Name"] == interface_name:
                        new_interface = interface
                        self.data[hostid]["Interface"].remove(interface)
            new_interface["Interface Name"] = interface_name

        if ip_address is None:
            ip_address = kwargs.get("IP Address", None)
        if ip_address is not None:
            if type(ip_address) is str:
                ip_address = IPv4Address(ip_address)
            if ip_address == BROADCAST_ADDRESS:
                if self.data[hostid]["Interface"] == []:
                    self.data[hostid].pop("Interface")
                return
            for interface in self.data[hostid]["Interface"]:
                if "IP Address" not in interface:
                    continue
                if interface["IP Address"] != ip_address:
                    continue
                if len(interface) > len(new_interface):
                    new_interface = interface
                elif len(interface) == len(new_interface):
                    for k in ["Interface Name", "Subnet"]:
                        if k in interface and k not in new_interface:
                            new_interface[k] = interface[k]
                self.data[hostid]["Interface"].remove(interface)
            new_interface["IP Address"] = ip_address

        if subnet is None:
            subnet = kwargs.get("Subnet", None)
        if subnet is not None:
            if type(subnet) is str:
                subnet = IPv4Network(subnet)
            new_interface["Subnet"] = subnet

        self.data[hostid]["Interface"].append(new_interface)

        if self.data[hostid]["Interface"] == [{}]:
            self.data[hostid].pop("Interface")

    def add_file_info(self,
                      hostid: str = None,
                      path: str = None,
                      name: str = None,
                      vendor: str = None,
                      version: str = None,
                      file_type: str = None,
                      user: str = None,
                      user_permissions: int = None,
                      group: str = None,
                      group_permissions: int = None,
                      default_permissions: int = None,
                      last_modified_time: datetime = None,
                      signed: bool = None,
                      density: float = None,
                      **kwargs):

        if hostid is None:
            hostid = str(len(self.data))
        if hostid not in self.data:
            self.data[hostid] = {"Files": []}
        elif "Files" not in self.data[hostid]:
            self.data[hostid]["Files"] = []

        new_file = {}
        if path is None:
            path = kwargs.get("Path", None)
        if path is not None:
            new_file["Path"] = path
            new_file["Known Path"] = CyEnums.Path.parse_string(path)

        if name is None:
            name = kwargs.get("File Name", None)
        if name is not None:
            new_file["File Name"] = name
            new_file["Known File"] = CyEnums.FileType.parse_string(name)

        if name is not None and path is not None:
            for file in self.data[hostid]["Files"]:
                if "File Name" in file and "Path" in file:
                    if name == file["File Name"] and path == file["Path"]:
                        self.data[hostid]["Files"].remove(file)
                        new_file = file
                        break

        if vendor is None:
            vendor = kwargs.get("Vendor", None)
        if vendor is not None:
            new_file["Vendor"] = CyEnums.Vendor.parse_string(vendor)

        if version is None:
            version = kwargs.get("Version", None)
        if version is not None:
            new_file["Version"] = version

        if file_type is None:
            file_type = kwargs.get("Type", None)
        if file_type is not None:
            if type(file_type) is str:
                file_type = CyEnums.FileType.parse_string(file_type)
            new_file["Type"] = file_type

        if user is None:
            user = kwargs.get("Username", None)
        if user is not None:
            new_file["Username"] = user

        if user_permissions is None:
            user_permissions = kwargs.get("User Permissions", None)
        if user_permissions is not None:
            new_file["User Permissions"] = user_permissions

        if group is None:
            group = kwargs.get("Group Name", None)
        if group is not None:
            new_file["Group Name"] = group

        if group_permissions is None:
            group_permissions = kwargs.get("Group Permissions", None)
        if group_permissions is not None:
            new_file["Group Permissions"] = group_permissions

        if default_permissions is None:
            default_permissions = kwargs.get("Default Permissions", None)
        if default_permissions is not None:
            new_file["Default Permissions"] = default_permissions

        if last_modified_time is None:
            last_modified_time = kwargs.get("Last Modified Time", None)
        if last_modified_time is not None:
            new_file["Last Modified Time"] = last_modified_time

        if signed is None:
            signed = kwargs.get('Signed', None)
        if signed is not None:
            new_file['Signed'] = signed

        if density is None:
            density = kwargs.get('Density', None)
        if density is not None:
            new_file['Density'] = density

        self.data[hostid]["Files"].append(new_file)

    def add_user_info(self,
                      hostid: str = None,
                      group_name: str = None,
                      gid: int = None,
                      username: str = None,
                      uid: int = None,
                      password: str = None,
                      password_hash: str = None,
                      password_hash_type: str = None,
                      logged_in: bool = None,
                      key_path: str = None,
                      **kwargs):

        if hostid is None:
            hostid = str(len(self.data))

        # only add user to dict if username or uid is known
        if username is not None or uid is not None:
            if hostid not in self.data:
                self.data[hostid] = {"User Info": []}
            elif "User Info" not in self.data[hostid]:
                self.data[hostid]["User Info"] = []


            new_user = {}

            if username is None:
                username = kwargs.get("Username", None)
            if username is not None:
                new_user["Username"] = username
                for user in self.data[hostid]["User Info"]:
                    if "Username" in user and user["Username"] == username:
                        new_user = user
                        self.data[hostid]["User Info"].remove(user)

            if uid is None:
                uid = kwargs.get("UID", None)
            if uid is not None:
                new_user["UID"] = uid

            if password is None:
                password = kwargs.get("Password", None)
            if password is not None:
                new_user["Password"] = password

            if password_hash is None:
                password_hash = kwargs.get("Password Hash", None)
            if password_hash is not None:
                new_user["Password Hash"] = password_hash

            if password_hash_type is None:
                password_hash_type = kwargs.get("Password Hash Type", None)
            if password_hash_type is not None:
                if type(password_hash_type) is str:
                    pw_enum = CyEnums.PasswordHashType
                    password_hash_type = pw_enum.parse_string(password_hash_type)
                new_user["Password Hash Type"] = password_hash_type

            if logged_in is None:
                logged_in = kwargs.get("Logged in", None)
            if logged_in is not None:
                new_user["Logged in"] = logged_in

            if key_path is None:
                key_path = kwargs.get("Key Path", None)
            if key_path is not None:
                new_user["Key Path"] = key_path


            new_group = {}
            if "Groups" not in new_user:
                new_user["Groups"] = []
            for groups in new_user["Groups"]:
                if (group_name is not None and "Group Name" in groups and group_name == groups["Group Name"]) \
                        or (gid is not None and "GID" in groups and gid == groups["GID"]):
                    new_group = groups
                    new_user["Groups"].remove(groups)
                    break

            if "Groups" in kwargs:
                new_user["Groups"] = kwargs.get("Groups")
            else:
                if group_name is not None:
                    new_group["Group Name"] = group_name
                    builtin_name = CyEnums.BuiltInGroups.parse_string(group_name)
                    if builtin_name is not CyEnums.BuiltInGroups.UNKNOWN:
                        new_group["Builtin Group"] = builtin_name
            if gid is not None:
                new_group["GID"] = gid

            if new_group != {}:
                new_user["Groups"].append(new_group)

            if new_user["Groups"] == []:
                new_user.pop("Groups")

            self.data[hostid]["User Info"].append(new_user)

        if gid is not None and group_name is not None and hostid in self.data and "User Info" in self.data[hostid]:
            for user in self.data[hostid]["User Info"]:
                if "Groups" in user:
                    for group in user["Groups"]:
                        if ("GID" in group and group["GID"] == gid) or ("Group Name" in group and group["Group Name"] == group_name):
                            group["GID"] = gid
                            group["Group Name"] = group_name
                            builtin_name = CyEnums.BuiltInGroups.parse_string(group_name)
                            if builtin_name is not CyEnums.BuiltInGroups.UNKNOWN:
                                group["Builtin Group"] = builtin_name

    def add_session_info(self,
                         hostid: str = None,
                         username: str = None,
                         session_id: int = None,
                         agent: str = None,
                         timeout: int = None,
                         pid: int = None,
                         session_type: str = None,
                         **kwargs):
        if hostid is None:
            hostid = str(len(self.data))
        if hostid not in self.data:
            self.data[hostid] = {"Sessions": []}
        elif "Sessions" not in self.data[hostid]:
            self.data[hostid]["Sessions"] = []

        new_session = {}
        if username is None:
            username = kwargs.get("Username", None)
        if username is not None:
            new_session["Username"] = username

        if session_id is None:
            session_id = kwargs.get("ID", None)
        if session_id is not None:
            new_session["ID"] = session_id

        if timeout is None:
            timeout = kwargs.get("Timeout", None)
        if timeout is not None:
            new_session["Timeout"] = timeout

        if pid is None:
            pid = kwargs.get("PID", None)
        if pid is not None:
            new_session["PID"] = pid
            self.add_process(hostid=hostid, pid=pid, username=username)

        if session_type is None:
            session_type = kwargs.get("Type", None)
        if session_type is not None:
            if type(session_type) is str:
                session_type = CyEnums.SessionType.parse_string(session_type)
            new_session["Type"] = session_type

        if agent is None:
            agent = kwargs.get("Agent", None)
            if agent is None:
                raise ValueError('Agent must be specified when a session is added to an observation')
        if agent is not None:
            new_session["Agent"] = agent

        if new_session not in self.data[hostid]["Sessions"]:
            # check we aren't adding duplicate
            self.data[hostid]["Sessions"].append(new_session)

    def combine_obs(self, obs):
        """Combines this Observation with another Observation

        Parameters
        ----------
        obs : Observation
           the other observation
        """
        if not isinstance(obs, dict):
            obs = obs.data
        for key, info in obs.items():
            if key == "success":
                self.set_success(info)
                continue
            if not isinstance(info, dict):
                self.add_key_value(key, info)
                continue
            if "Sessions" in info:
                for session_info in info["Sessions"]:
                    self.add_session_info(hostid=key, **session_info)
            if "Processes" in info:
                for process in info["Processes"]:
                    if 'Connections' in process:
                        for conn in process['Connections']:
                            self.add_process(hostid=key, **process, **conn)
                    else:
                        self.add_process(hostid=key, **process)
            if "User Info" in info:
                for user in info["User Info"]:
                    self.add_user_info(hostid=key, **user)
            if "Files" in info:
                for file_info in info["Files"]:
                    self.add_file_info(hostid=key, **file_info)
            if "Interface" in info:
                for interface in info["Interface"]:
                    self.add_interface_info(hostid=key, **interface)
            if "System info" in info:
                self.add_system_info(hostid=key, **info["System info"])

    def add_raw_obs(self, raw_obs):
        self.raw = raw_obs

    def add_key_value(self, key, val):
        self.data[key] = val

    def add_action_obs_pair(self, action, obs):
        """Adds an Action-Observation pair to this observation.

        This can be used to send back observations of multiple
        actions, in a single observation.

        Parameters
        ----------
        action : Action
            the action
        obs : Observation
            the observation
        """
        if "action_obs" not in self.data:
            self.data["action_obs"] = []
        self.data["action_obs"].append((action, obs))

    def has_multiple_obs(self) -> bool:
        """Returns whether Observation contains multiple nested observation

        Returns
        -------
        bool
            True if Observation has nested observations
        """
        return "action_obs" in self.data

    def get_nested_obs(self):
        """Returns any nested action, observation pairs

        Returns
        -------
        list((Action, Observation))
           any nested observations
        """
        return self.data.get("action_obs", [])

    def get_sessions(self) -> list:
        """Get list of info for each session in observation

        Returns
        -------
        list(dict)
            list of session info
        """
        sessions = []
        for k, v in self.data.items():
            if not isinstance(v, dict):
                continue
            if "Sessions" not in v:
                continue
            for session_info in v["Sessions"]:
                sessions.append(session_info)
        return sessions

    def get_agent_sessions(self, agent: str) -> list:
        """Get list of info for each agent session in observation

        Parameters
        ----------
        agent : str
            the agent to get session info for

        Returns
        -------
        list(dict)
            list of session info
        """
        sessions = []
        for session_info in self.get_sessions():
            if "Agent" not in session_info:
                continue
            if session_info["Agent"] != agent:
                continue
            sessions.append(session_info)
        return sessions

    def filter_addresses(self,
                         ips: Union[List[str], List[IPv4Address]] = None,
                         cidrs: Union[List[str], List[IPv4Network]] = None,
                         include_localhost: bool = True):
        """Filter observation, in place, to include only certain addresses

        This function will remove any observation information for addresses
        not in the list, and will remove all observations of Hosts which have
        had atleast one address observed but where none of the observed
        addresses are in the list.

        Parameters
        ----------
        ips : List[str] or List[IPv4Address], optional
            the ip addresses to keep, if None does not filter IP addresses
            (default=None)
        cidrs : List[str] or List[IPv4Network], optional
            the cidr addresses to keep, if None does not filter Cidr addresses
            (default=None)
        include_localhost : bool, optional
            If True and ips is not None, will include localhost address
            ('127.0.0.1') in IP addresses to keep (default=True)
        """
        # convert lists to set of str for fast lookup and consistent typing
        if ips is None:
            ip_set = set()
        else:
            ip_set = set([str(ip) for ip in ips])
            if include_localhost:
                ip_set.add('127.0.0.1')
            ip_set.add('0.0.0.0')

        if cidrs is None:
            cidr_set = set()
        else:
            cidr_set = set([str(c) for c in cidrs])
            if include_localhost:
                cidr_set.add('127.0.0.0/8')

        filter_hosts = []
        for obs_k, obs_v in self.data.items():
            if isinstance(obs_v, Observation):
                obs_v.filter_addresses(ips, cidrs, include_localhost)
            elif not isinstance(obs_v, dict):
                continue

            # v is observation of a host
            addr_observed = False
            valid_addr_observed = False

            filter_procs = []
            for i, proc in enumerate(obs_v.get("Processes", [])):
                if "Connections" not in proc:
                    continue
                for conn in proc["Connections"]:
                    for proc_k in ["local_address", "remote_address"]:
                        if proc_k in conn:
                            addr_observed = True
                            if str(conn[proc_k]) in ip_set:
                                valid_addr_observed = True
                            elif i not in filter_procs:
                                filter_procs.append(i)

            # Must remove indices in reverse order, else risk incorrect proc
            # being removed
            for p_idx in sorted(filter_procs, reverse=True):
                del obs_v["Processes"][p_idx]

            if "Processes" in obs_v and len(obs_v["Processes"]) == 0:
                del obs_v["Processes"]

            filter_interfaces = []
            for i, interface in enumerate(obs_v.get("Interface", [])):
                if "IP Address" in interface:
                    addr_observed = True
                    if str(interface["IP Address"]) in ip_set:
                        valid_addr_observed = True
                    else:
                        filter_interfaces.append(i)
                if "Subnet" in interface:
                    addr_observed = True
                    if str(interface["Subnet"]) in cidr_set:
                        valid_addr_observed = True
                    elif i not in filter_interfaces:
                        filter_interfaces.append(i)

            for i_idx in sorted(filter_interfaces, reverse=True):
                del obs_v["Interface"][i_idx]

            if "Interface" in obs_v and len(obs_v["Interface"]) == 0:
                del obs_v["Interface"]

            if len(list(obs_v.values())) == 0:
                filter_hosts.append(obs_k)

            # if ips is not None and addr_observed and not valid_addr_observed:
            #     filter_hosts.append(obs_k)

        for host_k in filter_hosts:
            del self.data[host_k]

    @property
    def success(self):
        return self.data["success"]

    @property
    def action_succeeded(self):
        return self.data["success"] == CyEnums.TrinaryEnum.TRUE

    def copy(self):
        obs_copy = Observation()
        for k, v in self.data.items():
            if isinstance(v, Observation):
                obs_copy.data[k] = v.copy()
            else:
                obs_copy.data[k] = deepcopy(v)
        return obs_copy

    def __str__(self):
        obs_str = pprint.pformat(self.data)
        return f"{self.__class__.__name__}:\n{obs_str}"

    def __eq__(self, other):
        if type(other) is not Observation:
            return False
        for k, v in self.data.items():
            if k not in other.data:
                return False
            other_v = other.data[k]
            if other_v != v:
                return False
        return True
