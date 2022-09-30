# Copyright DST Group. Licensed under the MIT license.
import enum


class TrinaryEnum(enum.Enum):
    TRUE = enum.auto()
    UNKNOWN = enum.auto()
    FALSE = enum.auto()

    @classmethod
    def parse_bool(cls, state_bool):
        if type(state_bool) is bool:
            if state_bool:
                return cls.TRUE
            else:
                return cls.FALSE
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if type(other) is bool:
            other = TrinaryEnum.parse_bool(other)
        if type(other) is not TrinaryEnum:
            return False
        if self.value == other.value:
            return True
        else:
            return False


class OperatingSystemPatch(enum.Enum):
    UNKNOWN = enum.auto()
    FILE_1 = enum.auto()
    Q147222 = enum.auto()
    KB911164 = enum.auto()
    MS17_010 = enum.auto()
    KB4500331 = enum.auto()
    KB4499149 = enum.auto()
    KB4499180 = enum.auto()
    KB4499164 = enum.auto()
    KB4499175 = enum.auto()


    @classmethod
    def parse_string(cls, patch_string):
        if patch_string.lower() == "file 1":
            return cls.FILE_1
        elif patch_string.lower() == "q147222":
            return cls.Q147222
        elif patch_string.lower() == "kb911164":
            return cls.KB911164
        elif patch_string.lower() == "ms17-010":
            return cls.MS17_010
        elif patch_string.lower() == "kb4500331":
            return cls.KB4500331
        elif patch_string.lower() == "kb4499149":
            return cls.KB4499149
        elif patch_string.lower() == "kb4499180":
            return cls.KB4499180
        elif patch_string.lower() == "kb4499164":
            return cls.KB4499164
        elif patch_string.lower() == "kb4499175":
            return cls.KB4499175

        return cls.UNKNOWN

    def __str__(self):
        return str(self.value)


class Architecture(enum.Enum):
    x86 = enum.auto()
    x64 = enum.auto()
    UNKNOWN = enum.auto()

    @classmethod
    def parse_string(cls, arch_string):
        if arch_string.lower() == "x86":
            return cls.x86
        if arch_string.lower() == "x64" or arch_string.lower() == "x86_64":
            return cls.x64
        else:
            return cls.UNKNOWN


class OperatingSystemType(enum.Enum):
    """An enum for representing the different possible Operating systems. """
    UNKNOWN = enum.auto()
    WINDOWS = enum.auto()
    LINUX = enum.auto()

    @classmethod
    def parse_string(cls, os_string):
        if os_string.lower() == "linux":
            return cls.LINUX
        elif "windows" in os_string.lower():
            return cls.WINDOWS
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class OperatingSystemDistribution(enum.Enum):
    """An enum for representing the different possible Operating systems. """
    UNKNOWN = enum.auto()
    WINDOWS_XP = enum.auto()
    WINDOWS_SVR_2003 = enum.auto()
    WINDOWS_SVR_2008 = enum.auto()
    WINDOWS_7 = enum.auto()
    WINDOWS_8 = enum.auto()
    WINDOWS_10 = enum.auto()
    UBUNTU = enum.auto()
    KALI = enum.auto()
    WINDOWS_SVR_2003SP2 = enum.auto()
    WINDOWS_VISTA = enum.auto()
    WINDOWS_SVR_2008SP1 = enum.auto()
    WINDOWS_SVR_2008R2 = enum.auto()
    WINDOWS_7SP1 = enum.auto()

    @classmethod
    def parse_string(cls, os_string):
        os_string = os_string.lower()
        if os_string == "windows xp":
            return cls.WINDOWS_XP
        elif os_string == "windows server 2003":
            return cls.WINDOWS_SVR_2003
        elif "windows server 2008" in os_string or os_string == 'windows_svr_2008':
            return cls.WINDOWS_SVR_2008
        elif os_string == "windows 7":
            return cls.WINDOWS_7
        elif os_string == "windows 8":
            return cls.WINDOWS_8
        elif os_string == "windows 10":
            return cls.WINDOWS_10
        elif "ubuntu" in os_string:
            return cls.UBUNTU
        elif "kali" in os_string:
            return cls.KALI
        elif "2003sp2" in os_string and "window" in os_string:
            return cls.WINDOWS_SVR_2003SP2
        elif "vista" in os_string and "window" in os_string:
            return cls.WINDOWS_VISTA
        elif "svr 2008sp1" in os_string and "window" in os_string:
            return cls.WINDOWS_SVR_2008SP1
        elif "svr 2008r2" in os_string and "window" in os_string:
            return cls.WINDOWS_SVR_2008R2
        elif "7sp1" in os_string and "window" in os_string:
            return cls.WINDOWS_7SP1
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class OperatingSystemVersion(enum.Enum):
    """An enum for representing the different possible Operating systems. """
    UNKNOWN = enum.auto()
    SP0 = enum.auto()
    SP1 = enum.auto()
    SP2 = enum.auto()
    SP3 = enum.auto()
    U18_04_3 = enum.auto()
    U18_04 = enum.auto()
    U8_04 = enum.auto()
    K2019_1 = enum.auto()
    K2019_2 = enum.auto()
    K2019_4 = enum.auto()
    W6_2_9200_16384 = enum.auto()
    W6_1_7601 = enum.auto()
    NT6_1 = enum.auto()

    @classmethod
    def parse_string(cls, os_string):
        os_string = os_string.lower()
        if os_string == "sp0":
            return cls.SP0
        elif os_string == "sp1":
            return cls.SP1
        elif os_string == "sp2":
            return cls.SP2
        elif os_string == "sp3":
            return cls.SP3
        elif os_string == "6.2.9200.16384":
            return cls.W6_2_9200_16384
        elif "6.1.7601" in os_string or os_string == 'w6_1_7601':
            return cls.W6_1_7601
        elif os_string == "18.04.3" or os_string == 'u18_04_3':
            return cls.U18_04_3
        elif os_string == "18.04":
            return cls.U18_04
        elif os_string == "8.04":
            return cls.U8_04
        elif os_string == "2019.1":
            return cls.K2019_1
        elif os_string == "2019.2":
            return cls.K2019_2
        elif "4.19.0-kali4" in os_string or os_string == "k2019_4":
            return cls.K2019_4
        elif os_string == "nt6.1":
            return cls.NT6_1
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class OperatingSystemKernelVersion(enum.Enum):
    """An enum for representing the different possible Operating systems. """
    UNKNOWN = enum.auto()
    L2_6_24 = enum.auto()
    L4_15_0_1057_AWS = enum.auto()
    L5_2_0 = enum.auto()
    L5_3_0 = enum.auto()

    @classmethod
    def parse_string(cls, os_string):
        os_string = os_string.lower()
        if os_string == "linux 2.6.24":
            return cls.L2_6_24
        elif os_string == "4.15.0-1057-aws":
            return cls.L4_15_0_1057_AWS
        elif os_string == "linux 5.2.0":
            return cls.L5_2_0
        elif os_string == "linux 5.3.0":
            return cls.L5_3_0
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class ProcessName(enum.Enum):
    UNKNOWN = enum.auto()
    SVCHOST = enum.auto()
    INIT = enum.auto()
    CRON = enum.auto()
    UDEVD = enum.auto()
    JSVC = enum.auto()
    SSHD = enum.auto()
    MYSQLD_SAFE = enum.auto()
    MYSQLD = enum.auto()
    SMBD = enum.auto()
    SMTP = enum.auto()
    FEMITTER = enum.auto()
    APACHE2 = enum.auto()
    EXPLORER = enum.auto()
    LSASS = enum.auto()
    WINLOGON = enum.auto()
    SMSS = enum.auto()
    SYSTEM = enum.auto()
    SYSTEM_IDLE_PROCESS = enum.auto()
    SERVICES = enum.auto()
    SHELL = enum.auto()
    TELNET = enum.auto()
    SLEEP = enum.auto()
    JAVA = enum.auto()
    PS = enum.auto()
    VELOCLIENT = enum.auto()
    POWERSHELL = enum.auto()
    CMD = enum.auto()

    @classmethod
    def parse_string(cls, name):
        name = name.lower()
        if name == "svchost" or name == "svchost.exe":
            return cls.SVCHOST
        elif name == "init":
            return cls.INIT
        elif name == "cron":
            return cls.CRON
        elif name == "udevd":
            return cls.UDEVD
        elif name == "jsvc":
            return cls.JSVC
        elif name == "sshd" or name == "sshd.exe":
            return cls.SSHD
        elif name == "mysqld_safe":
            return cls.MYSQLD_SAFE
        elif name == "mysqld":
            return cls.MYSQLD
        elif name == "smbd":
            return cls.SMBD
        elif name == "smtp":
            return cls.SMTP
        elif name == "femitter.exe":
            return cls.FEMITTER
        elif name == "apache2":
            return cls.APACHE2
        elif name == "explorer" or name == "explorer.exe":
            return cls.EXPLORER
        elif name == "lsass" or name == "lsass.exe":
            return cls.LSASS
        elif name == "winlogon" or name == "winlogon.exe":
            return cls.WINLOGON
        elif name == "smss" or name == "smss.exe":
            return cls.SMSS
        elif name == "system":
            return cls.SYSTEM
        elif name == "system idle process" or name == "system process":
            return cls.SYSTEM_IDLE_PROCESS
        elif name == "services" or name == "services.exe":
            return cls.SERVICES
        elif name == "bash" or name == "sh" or name == "sh.exe":
            return cls.SHELL
        elif name == "telnet":
            return cls.TELNET
        elif name == "sleep":
            return cls.SLEEP
        elif name == "java":
            return cls.JAVA
        elif name == "ps":
            return cls.PS
        elif name == "velociraptorclient":
            return cls.VELOCLIENT
        elif name == "powershell.exe" or name == "powershell":
            return cls.POWERSHELL
        elif name == "cmd.exe" or name == "cmd":
            return cls.CMD
        else:
            return cls.UNKNOWN


class ProcessType(enum.Enum):
    """An enum for representing the different types of services. """
    UNKNOWN = enum.auto()
    SSH = enum.auto()
    SVCHOST = enum.auto()
    SMB = enum.auto()
    SMTP = enum.auto()
    FEMITTER = enum.auto()
    WEBSERVER = enum.auto()
    NETCAT = enum.auto()
    RDP = enum.auto()
    REVERSE_SESSION_HANDLER = enum.auto()
    REVERSE_SESSION = enum.auto()
    MYSQL = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        service_string = service_string.lower()
        if service_string == "ssh" or service_string == "sshd" or service_string == "sshd.exe":
            return cls.SSH
        elif service_string == "svchost":
            return cls.SVCHOST
        elif service_string == "smtp":
            return cls.SMTP
        elif service_string == "femitter":
            return cls.FEMITTER
        elif service_string == "mysql":
            return cls.MYSQL
        elif service_string == "smb":
            return cls.SMB
        elif service_string.replace(" ", "") == "webserver":
            return cls.WEBSERVER
        elif service_string == "netcat":
            return cls.NETCAT
        elif service_string == "rdp":
            return cls.RDP
        elif service_string == "reverse_session_handler":
            return cls.REVERSE_SESSION_HANDLER
        elif service_string == "reverse_session":
            return cls.REVERSE_SESSION
        elif service_string == "http":
            return cls.WEBSERVER
        elif service_string == "https":
            return cls.WEBSERVER
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


# Potentially split this into separate Enums for each ProcessType at later date
class ProcessVersion(enum.Enum):
    OPENSSH_1_3 = enum.auto()
    SVC10_0_17763_1 = enum.auto()
    SAMBA_3_0_20_DEB = enum.auto()
    SMBv1 = enum.auto()
    APACHE_TOMCAT = enum.auto()
    PYTHON_SERVER = enum.auto()
    HARAKA_2_7_0 = enum.auto()
    HARAKA_2_8_9 = enum.auto()
    UNKNOWN = enum.auto()

    @classmethod
    def parse_string(cls, version_string):
        if version_string is not None and isinstance(version_string, str):
            version_string = version_string.lower()

        if version_string == "openssh 1.3":
            return cls.OPENSSH_1_3
        elif version_string == "10.0.17763.1":
            return cls.SVC10_0_17763_1
        elif version_string == "samba 3.0.20-debian":
            return cls.SAMBA_3_0_20_DEB
        elif version_string == "apache tomcat":
            return cls.APACHE_TOMCAT
        elif version_string == "python simplehttpserver":
            return cls.PYTHON_SERVER
        elif version_string == "smbv1":
            return cls.SMBv1
        elif version_string == "haraka 2.7.0":
            return cls.HARAKA_2_7_0
        elif version_string is not None:
            return version_string
        else:
            return cls.UNKNOWN


class TransportProtocol(enum.Enum):
    """An enum for representing the different types of services. """
    UNKNOWN = enum.auto()
    TCP = enum.auto()
    UDP = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        service_string = service_string.lower()
        if service_string == "tcp":
            return cls.TCP
        elif service_string == "udp":
            return cls.UDP
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class BuiltInGroups(enum.Enum):
    UNKNOWN = enum.auto()
    USERS = enum.auto()
    WEBSERVER = enum.auto()
    ROOT = enum.auto()
    SHADOW = enum.auto()
    ADMINISTRATORS = enum.auto()

    @classmethod
    def parse_string(cls, group_string):
        group_string = group_string.lower()
        if group_string == "users":
            return cls.USERS
        elif group_string == "web server users":
            return cls.WEBSERVER
        elif group_string == "root":
            return cls.ROOT
        elif group_string == "shadow":
            return cls.SHADOW
        elif group_string == "administrators":
            return cls.ADMINISTRATORS
        else:
            return cls.UNKNOWN


class SessionType(enum.Enum):
    """An enum for representing the different types of sessions. """
    UNKNOWN = enum.auto()
    SSH = enum.auto()
    SHELL = enum.auto()
    METERPRETER = enum.auto()
    MSF_SHELL = enum.auto()
    MSF_SERVER = enum.auto()
    VELOCIRAPTOR_CLIENT = enum.auto()
    VELOCIRAPTOR_SERVER = enum.auto()
    LOCAL_SHELL = enum.auto()
    RED_ABSTRACT_SESSION = enum.auto()
    RED_REVERSE_SHELL = enum.auto()
    GREY_SESSION = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        service_string = service_string.lower()
        if service_string == "ssh":
            return cls.SSH
        elif service_string == "shell":
            return cls.SHELL
        elif service_string == "meterpreter":
            return cls.METERPRETER
        elif service_string == "msf shell" or service_string == "msf_shell":
            return cls.MSF_SHELL
        elif service_string == "metasploitserver":
            return cls.MSF_SERVER
        elif service_string == "velociraptorclient":
            return cls.VELOCIRAPTOR_CLIENT
        elif service_string == "velociraptorserver":
            return cls.VELOCIRAPTOR_SERVER
        elif service_string == "redabstractsession":
            return cls.RED_ABSTRACT_SESSION
        elif service_string == "red_reverse_shell":
            return cls.RED_REVERSE_SHELL
        elif service_string.replace(" ", "").replace("_", "") == "localshell":
            return cls.LOCAL_SHELL
        elif service_string == "green_session":
            return cls.GREY_SESSION
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class Path(enum.Enum):
    UNKNOWN = enum.auto()
    WINDOWS = enum.auto()
    WINDOWS_SYSTEM = enum.auto()
    SYSTEM = enum.auto()
    TEMP = enum.auto()
    SBIN = enum.auto()
    BIN = enum.auto()
    USR_SBIN = enum.auto()
    USR_BIN = enum.auto()
    ETC = enum.auto()
    ADMINISTRATOR_DESKTOP = enum.auto()
    WEBSERVER = enum.auto()
    EXPLOIT = enum.auto()

    @classmethod
    def parse_string(cls, path_string):
        path_string = path_string.lower()
        if path_string == "system":
            return cls.SYSTEM
        elif path_string == "c:/windows/system32/":
            return cls.WINDOWS_SYSTEM
        elif path_string == "c:\\windows\\system32\\":
            return cls.WINDOWS_SYSTEM
        elif path_string == "c:/windows/" or path_string == "c:\\windows\\":
            return cls.WINDOWS
        elif path_string == "/tmp/" or path_string == "c:\\temp\\":
            return cls.TEMP
        elif path_string == "/sbin/" or path_string == "/sbin":
            return cls.SBIN
        elif path_string == "/bin/" or path_string == "/bin":
            return cls.BIN
        elif path_string == "/usr/sbin/" or path_string == "/usr/sbin":
            return cls.USR_SBIN
        elif path_string == "/usr/bin/" or path_string == "/usr/bin":
            return cls.USR_BIN
        elif path_string == "/etc/" or path_string == "/etc":
            return cls.ETC
        elif path_string == "c:\\users\\administrator\\desktop\\":
            return cls.ADMINISTRATOR_DESKTOP
        elif path_string == "/tmp/webserver/":
            return cls.WEBSERVER
        elif path_string == "/usr/share/exploitdb/exploits/linux/local/":
            return cls.EXPLOIT
        else:
            return cls.UNKNOWN


class ProcessState(enum.Enum):
    """An enum for representing the different types of services. """
    UNKNOWN = enum.auto()
    OPEN = enum.auto()
    CLOSED = enum.auto()
    FILTERED = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        service_string = service_string.lower()
        if service_string == "open":
            return cls.OPEN
        elif service_string == "closed":
            return cls.CLOSED
        elif service_string == "filtered":
            return cls.FILTERED
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class FileType(enum.Enum):
    UNKNOWN = enum.auto()
    SVCHOST = enum.auto()
    PASSWD = enum.auto()
    SHADOW = enum.auto()
    FLAG = enum.auto()
    SMBCLIENT = enum.auto()
    NMAP = enum.auto()
    DirtyCowCode = enum.auto()
    DirtyCowExe = enum.auto()
    PYTHON = enum.auto()
    GCC = enum.auto()
    UDEV141CODE = enum.auto()
    UDEV141EXE = enum.auto()
    NC_REVERSE_SHELL = enum.auto()
    NC = enum.auto()

    @classmethod
    def parse_string(cls, name_string):
        name_string = name_string.lower()
        if name_string == "svchost":
            return cls.SVCHOST
        elif name_string == "passwd":
            return cls.PASSWD
        elif name_string == "shadow":
            return cls.SHADOW
        elif name_string == "flag":
            return cls.FLAG
        elif name_string == "smbclient":
            return cls.SMBCLIENT
        elif name_string == "nmap":
            return cls.NMAP
        elif name_string == "dirty_cow_c_file":
            return cls.DirtyCowCode
        elif name_string == "python":
            return cls.PYTHON
        elif name_string == "gcc":
            return cls.GCC
        elif name_string == "udev < 1.4.1":
            return cls.UDEV141CODE
        elif name_string == "nc_reverse_shell":
            return cls.NC_REVERSE_SHELL
        elif name_string == "nc":
            return cls.NC
        return cls.UNKNOWN


class FileVersion(enum.Enum):
    UNKNOWN = enum.auto()
    U4_2_4_1 = enum.auto()
    D9_2_1_21 = enum.auto()
    OPENBSD = enum.auto()

    @classmethod
    def parse_string(cls, name_string):
        name_string = name_string.lower()
        if name_string == "ubuntu 4.2.4-1":
            return cls.U4_2_4_1
        elif name_string == "debian 9.2.1-21":
            return cls.D9_2_1_21
        elif name_string == "openbsd":
            return cls.OPENBSD
        return cls.UNKNOWN


class FileExt(enum.Enum):
    ELF = enum.auto()
    UNKNOWN = enum.auto()

    @classmethod
    def parse_string(cls, name_string):
        if name_string.lower() == "elf":
            return cls.ELF
        return cls.UNKNOWN


class Vulnerability(enum.Enum):
    UNKNOWN = enum.auto()

    @classmethod
    def parse_string(cls, vuln_string):
        return cls.UNKNOWN


class Vendor(enum.Enum):
    UNKNOWN = enum.auto()

    @classmethod
    def parse_string(cls, vendor_string):
        return cls.UNKNOWN


class PasswordHashType(enum.Enum):
    UNKNOWN = enum.auto()
    MD5 = enum.auto()
    SHA512 = enum.auto()
    NTLM = enum.auto()

    @classmethod
    def parse_string(cls, hash_string):
        hash_string = hash_string.lower()
        if hash_string == "md5":
            return cls.MD5
        elif hash_string == 'sha512':
            return cls.SHA512
        elif hash_string == 'ntlm':
            return cls.NTLM
        return cls.UNKNOWN


class InterfaceType(enum.Enum):
    UNKNOWN = enum.auto()
    BROADCAST = enum.auto()
    LOCAL = enum.auto()

    @classmethod
    def parse_string(cls, interface_string):
        if interface_string.lower() == "broadcast":
            return cls.BROADCAST
        elif interface_string.lower() == "local":
            return cls.LOCAL
        return cls.UNKNOWN


class AppProtocol(enum.Enum):
    UNKNOWN = enum.auto()
    HTTP = enum.auto()
    HTTPS = enum.auto()
    SSH = enum.auto()
    JPV13 = enum.auto()
    TCP = enum.auto()
    MYSQL = enum.auto()
    NETBIOS_SSN = enum.auto()
    MICROSOFT_DS = enum.auto()
    RPC = enum.auto()

    @classmethod
    def parse_string(cls, protocol_string):
        protocol_string = protocol_string.lower()
        if protocol_string == "http":
            return cls.HTTP
        elif protocol_string == "https":
            return cls.HTTPS
        elif protocol_string == "ssh":
            return cls.SSH
        elif protocol_string == "jpv13":
            return cls.JPV13
        elif protocol_string == "tcp":
            return cls.TCP
        elif protocol_string == "mysql":
            return cls.MYSQL
        elif protocol_string == "netbios-ssn":
            return cls.NETBIOS_SSN
        elif protocol_string == "microsoft-ds":
            return cls.MICROSOFT_DS
        elif protocol_string == "rpc":
            return cls.RPC
        return cls.UNKNOWN


class QueryType(enum.Enum):
    SYNC = enum.auto()
    ASYNC = enum.auto()

    @classmethod
    def parse_string(cls, query_string):
        if query_string.lower() == "sync":
            return cls.SYNC
        elif query_string.lower() == "async":
            return cls.ASYNC

## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.

class DecoyType(enum.Flag):
    NONE = 0
    ESCALATE = enum.auto()
    EXPLOIT = enum.auto()
    SANDBOXING_EXPLOIT = enum.auto()
