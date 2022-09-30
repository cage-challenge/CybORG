from typing import Union, Any
from ipaddress import IPv4Address, IPv4Network

from CybORG.Shared.Enums import OperatingSystemType, SessionType

class ObservationWrapper():
    
    def __init__(self, obs: dict):
        self.success = obs.get('success')
        self.hosts = {str(k):v for k,v in obs.items() if k != 'success'}

    def _get_host_attribute(self,host: str, attr: str, default: Union[list,dict]=[]) \
            -> Union[list,dict]:
        host = self.hosts.get(str(host))
        attr = host.get(attr,default) if host is not None else default

        return attr

    def get_interfaces(self,host: str) -> list:
        return self._get_host_attribute(str(host),'Interface')

    def get_processes(self,host: str) -> list:
        return self._get_host_attribute(str(host),'Processes')

    def get_sessions(self,host: str) -> list:
        return self._get_host_attribute(str(host),'Sessions')

    def get_os_info(self,host: str) -> dict:
        return self._get_host_attribute(str(host),'System info', default={})

    def get_ip(self,host: str) -> Union[IPv4Address,None]:
        interfaces = self.get_interfaces(str(host))
        ip = interfaces[0].get('IP Address') if len(interfaces) > 0 else None

        return ip

    def get_subnet(self,host: str) -> Union[IPv4Network,None]:
        interfaces = self.get_interfaces(str(host))
        cidr = interfaces[0].get('Subnet') if len(interfaces) > 0 else None

        return cidr

    def has_red_access(self, host: str, only_root=False) -> bool:
        sessions = self.get_sessions(str(host))
        access_list = [sess for sess in sessions if sess.get('Agent') == 'Red']

        if only_root:
            access_list = [sess for sess in access_list if sess.get('Username') \
                    in ('SYSTEM', 'root')]
        
        access = True if len(access_list) > 0 else False

        return access

    def get_hostname(self, host: str) -> str:
        os_info = self.get_os_info(str(host))

        return os_info.get('Hostname')

    def get_os(self, host: str) -> Union[OperatingSystemType,None]:
        os_info = self.get_os_info(str(host))

        return os_info.get('OSType')

