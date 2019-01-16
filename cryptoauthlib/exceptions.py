# -*- coding: utf-8 -*-


class CryptoError(Exception):
    pass


class ConfigZoneLockedError(CryptoError):
    def __init__(self, *args):
        super().__init__("Config Zone Locked", *args)


class DataZoneLockedError(CryptoError):
    def __init__(self, *args):
        super().__init__("Configuration Enabled", *args)


class WakeFailedError(CryptoError):
    def __init__(self, *args):
        super().__init__("Device Wake failed", *args)


class CheckmacVerifyFailedError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status byte indicates CheckMac/Verify failure "
            "(status byte = 0x01)",
            *args
        )


class ParseError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status byte indicates parsing error "
            "(status byte = 0x03)",
            *args
        )

class WatchDogAboutToExpireError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status indicate insufficient time to execute the given "
            "commmand begore watchdog timer will expire (status byte = 0xEE)",
            *args
        )

class CrcError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status byte indicates CRC error (status byte = 0xFF)",
            *args
        )


class StatusUnknownError(CryptoError):
    def __init__(self, *args):
        super().__init__("Response status byte is unknown", *args)


class EccFaultError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status byte is ECC fault (status byte = 0x05)",
            *args
        )


class SelfTestError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "response status byte is Self Test Error, "
            "chip in failure mode (status byte = 0x07)",
            *args
        )


class HealthTestError(CryptoError):
    def __init__(self, *args):
        super().__init__("random number generator health test error", *args)


class FunctionError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Function could not execute due to incorrect condition / state.",
            *args
        )


class GenericError(CryptoError):
    def __init__(self, *args):
        super().__init__("unspecified error", *args)


class BadArgumentError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "bad argument (out of range, null pointer, etc.)",
            *args
        )


class InvalidIdentifierError(CryptoError):
    def __init__(self, *args):
        super().__init__("invalid device id, id not set", *args)


class InvalidSizeError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Count value is out of range or greater than buffer size.",
            *args
        )


class BadCrcError(CryptoError):
    def __init__(self, *args):
        super().__init__("incorrect CRC received", *args)


class ReceiveError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Timed out while waiting for response. "
            "Number of bytes received is > 0.",
            *args
        )


class NoResponseError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "error while the Command layer is polling for a command response.",
            *args
        )


class ResyncWithWakeupError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Re-synchronization succeeded, but only after generating a Wake-up",
            *args
        )


class ParityError(CryptoError):
    def __init__(self, *args):
        super().__init__("for protocols needing parity", *args)


class TransmissionTimeoutError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "for Microchip PHY protocol, "
            "timeout on transmission waiting for master",
            *args
        )


class ReceiveTimeoutError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "for Microchip PHY protocol, timeout on receipt waiting for master",
            *args
        )


class CommunicationError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Communication with device failed. "
            "Same as in hardware dependent modules.",
            *args
        )


class TimeOutError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Timed out while waiting for response. "
            "Number of bytes received is 0.",
            *args
        )


class BadOpcodeError(CryptoError):
    def __init__(self, *args):
        super().__init__("Opcode is not supported by the device",
                         *args)


class ExecutionError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "chip was in a state where it could not execute the command, response "
            "status byte indicates command execution error (status byte = 0x0F)",
            *args
        )


class UnimplementedError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "Function or some element of it hasn't been implemented yet",
            *args
        )


class AssertionFailure(CryptoError):
    def __init__(self, *args):
        super().__init__("Code failed run-time consistency check", *args)


class TransmissionError(CryptoError):
    def __init__(self, *args):
        super().__init__("Failed to write", *args)


class ZoneNotLockedError(CryptoError):
    def __init__(self, *args):
        super().__init__("required zone was not locked", *args)


class NoDevicesFoundError(CryptoError):
    def __init__(self, *args):
        super().__init__(
            "For protocols that support device discovery (kit protocol), "
            "no devices were found",
            *args
        )


class UnsupportedDeviceError(CryptoError):
    def __init__(self, *args):
        super().__init__(*args)
