#

class EphemeralPort:
    def __eq__(self, other):
        if issubclass(type(other), EphemeralPort):
            return True
        return False

class IANAEphemeralPort(EphemeralPort):
    def __eq__(self, other):
        if issubclass(type(other), EphemeralPort):
            return True
        if type(other) is int:
            if other >= 49152 and other <= 65535:
                return True
        return False

class Win2008EphemeralPort(EphemeralPort):
    def __eq__(self, other):
        if issubclass(type(other), EphemeralPort):
            return True
        if type(other) is int:
            if other >= 1025 and other <= 60000:
                return True
        return False

class LinuxEphemeralPort(EphemeralPort):
    def __eq__(self, other):
        if issubclass(type(other), EphemeralPort):
            return True
        if type(other) is int:
            if other >= 32768 and other <= 60999:
                return True
        return False

class BSDEphemeralPort(EphemeralPort):
    def __eq__(self, other):
        if issubclass(type(other), EphemeralPort):
            return True
        if type(other) is int:
            if other >= 1024 and other <= 5000:
                return True
        return False

class PID:
    def __eq__(self, other):
        if issubclass(type(other), PID):
            return True
        if type(other) is int:
            if other <= 32768:
                return True
        return False