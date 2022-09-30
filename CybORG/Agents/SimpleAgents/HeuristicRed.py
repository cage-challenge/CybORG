import random
from CybORG.Shared.Actions import DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, PrivilegeEscalate, Impact

class HeuristicRed():
    def __init__(self, session=0, priority=None):
        self.priority = priority
        self.parameters = {
                'session':session,
                'agent':'Red',
                }

        self.killchain = [DiscoverNetworkServices,ExploitRemoteService,
                PrivilegeEscalate,Impact]

        self.last_action = None
        self.history = []
        self.active_ip = None

        self.known_subnets = set()
        self.unexplored_subnets = set()
        self.ip_map = {}
        self.ip_status = {}

    def get_action(self,obs):
        success = obs['success']
        if success == False:
            # Needs to be failure first because unknown (initial obs) counts as true
            self._process_last_action_failure()
        else:
            self._process_last_action_success() if self.last_action else None
            self._process_new_ips(obs)
        
        action = self._advance_killchain()

        return action

    def _process_last_action_success(self):
        action = self.last_action
        name = self.last_action.__class__.__name__
        if name == 'DiscoverRemoteSystems':
            subnet = action.subnet
            self.unexplored_subnets.remove(subnet)
        elif name in ('DiscoverNetworkServices','ExploitRemoteService'):
            # Advance killchain
            ip = action.ip_address
            self.ip_status[ip] += 1
        else:
            # Get ip from hostname and advance killchain
            ip = self._get_ip(action.hostname)
            self.ip_status[ip] += 1 if self.ip_status[ip] < 3 else 0

    def _process_last_action_failure(self):
        action = self.last_action
        name = self.last_action.__class__.__name__
        if name in ('PrivilegeEscalate','Impact'):
            ip = self._get_ip(action.hostname)
            self.ip_status[ip] = 1
        elif name == 'ExploitRemoteService':
            # Assuming host is Defender
            self.ip_status[action.ip_address] = 3
        else:
            raise NotImplementedError('Scans are not supposed to fail.')

    def _process_new_ips(self,obs):
        for hostid in obs:
            if hostid == 'success':
                continue
            host = obs[hostid]
            for interface in host.get('Interface',[]):
                subnet = interface.get('Subnet')
                if (subnet not in self.known_subnets) and (subnet is not None):
                    self.known_subnets.add(subnet)
                    self.unexplored_subnets.add(subnet)

                ip = interface.get('IP Address')
                assert ip is not None
                if ip not in self.ip_status:
                    self.ip_status[ip] = 0

                sysinfo = host.get('System info')
                hostname = sysinfo.get('Hostname') if sysinfo else None

                if ip not in self.ip_map:
                    self.ip_map[ip] = hostname
                elif self.ip_map[ip] is None:
                    self.ip_map[ip] = hostname

    def _advance_killchain(self):
        if self.unexplored_subnets:
            subnet = random.choice(list(self.unexplored_subnets))
            action = DiscoverRemoteSystems(subnet=subnet,**self.parameters)
        else:

            ip = self._choose_ip()
            
            action = self._choose_exploit(ip)
            if ip not in self.ip_status:
                self.ip_status[ip] = 0
       
        self.last_action = action
        self.history.append(action)
        return action

    def _choose_ip(self):
        if self.active_ip is None:
            self.active_ip = random.choice(list(self.ip_status.keys()))

        ip = self.active_ip
        status = self.ip_status[ip]
        if (status < 3) or (self.ip_map[ip] == 'Op_Server0'):
            pass
        else:
            valid_ips = [ip for ip in self.ip_status if self.ip_status[ip] < 3]
            ip = self.active_ip = random.choice(valid_ips) if valid_ips else None

        self.active_ip = ip
        assert ip in self.ip_status
        return ip

    def _choose_exploit(self,ip):
        status = self.ip_status[ip]
        command = self.killchain[status]
        if status == 0:
            action = command(ip_address=ip,**self.parameters)
        elif status == 1: 
            action = command(ip_address=ip, priority=self.priority,**self.parameters)
        else:
            hostname = self.ip_map[ip]
            action = command(hostname=hostname,**self.parameters)
        
        return action

    def _get_ip(self,hostname):
        for ip in self.ip_map:
            if self.ip_map[ip] == hostname:
                break
        else:
            raise NotImplementedError('Hostname missing from ip_map')
        return ip
