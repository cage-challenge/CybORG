from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Simulator.Actions import *

agents = ['Red', 'Blue', 'Green']

hosts = [
        'User0',
        'User1',
        'User2',
        'User3',
        'User4',
        'Enterprise0',
        'Enterprise1',
        'Enterprise2',
        'Defender',
        'Op_Server0',
        'Op_Host0',
        'Op_Host1',
        'Op_Host2',
        ]

subnets = {
        'User': hosts[:5],
        'Enterprise': hosts[5:9],
        'Operational': hosts[9:]
        }

red_actions = [
        DiscoverRemoteSystems,
        DiscoverNetworkServices,
        ExploitRemoteService,
        PrivilegeEscalate,
        Impact,
        BlueKeep,
        EternalBlue,
        FTPDirectoryTraversal,
        HarakaRCE,
        HTTPRFI,
        HTTPSRFI,
        SQLInjection,
        SSHBruteForce,
        ]

blue_actions = [
        Monitor,
        Analyse,
        Remove,
        Restore,
        Misinform,
        DecoyApache,
        DecoyFemitter,
        DecoyHarakaSMPT,
        DecoySmss,
        DecoySSHD,
        DecoySvchost,
        DecoyTomcat,
        DecoyVsftpd,
        ]

green_actions = [GreenConnection,]

actions = dict(zip(agents, [red_actions, blue_actions, green_actions]))

windows_hosts = ['User0', 'User1', 'User2', 'Enterprise1', 'Enterprise2']
get_os_type = lambda x : OperatingSystemType.WINDOWS if x in windows_hosts \
        else OperatingSystemType.LINUX
os_map = {h:get_os_type(h) for h in hosts}

scenario2 = {
        'Agents': agents,
        'Hosts': hosts,
        'Subnets': subnets,
        'Actions': actions,
        'OS_Map': os_map,
        }
