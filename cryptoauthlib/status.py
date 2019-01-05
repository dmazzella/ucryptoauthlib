# -*- coding: utf-8 -*-
# pylint: disable=E0401
from micropython import const

from cryptoauthlib import exceptions as ATCA_EXECUTIONS

""" status codes """

# Function succeeded.
ATCA_SUCCESS = const(0x00)
ATCA_CONFIG_ZONE_LOCKED = const(0x01)
ATCA_DATA_ZONE_LOCKED = const(0x02)
# response status byte indicates CheckMac failure (status byte = 0x01)
ATCA_WAKE_FAILED = const(0xD0)
# response status byte indicates CheckMac failure (status byte = 0x01)
ATCA_CHECKMAC_VERIFY_FAILED = const(0xD1)
# response status byte indicates parsing error (status byte = 0x03)
ATCA_PARSE_ERROR = const(0xD2)
# response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)
ATCA_STATUS_CRC = const(0xD4)
# response status byte is unknown
ATCA_STATUS_UNKNOWN = const(0xD5)
# response status byte is ECC fault (status byte = 0x05)
ATCA_STATUS_ECC = const(0xD6)
# response status byte is Self Test Error, chip in failure mode (status byte = 0x07)
ATCA_STATUS_SELFTEST_ERROR = const(0xD7)
# Function could not execute due to incorrect condition / state.
ATCA_FUNC_FAIL = const(0xE0)
# unspecified error
ATCA_GEN_FAIL = const(0xE1)
# bad argument (out of range, null pointer, etc.)
ATCA_BAD_PARAM = const(0xE2)
# invalid device id, id not set
ATCA_INVALID_ID = const(0xE3)
# Count value is out of range or greater than buffer size.
ATCA_INVALID_SIZE = const(0xE4)
# CRC error in data received from device
ATCA_RX_CRC_ERROR = const(0xE5)
# Timed out while waiting for response. Number of bytes received is > 0.
ATCA_RX_FAIL = const(0xE6)
# Not an error while the Command layer is polling for a command response.
ATCA_RX_NO_RESPONSE = const(0xE7)
# Re-synchronization succeeded, but only after generating a Wake-up
ATCA_RESYNC_WITH_WAKEUP = const(0xE8)
# for protocols needing parity
ATCA_PARITY_ERROR = const(0xE9)
# for Microchip PHY protocol, timeout on transmission waiting for master
ATCA_TX_TIMEOUT = const(0xEA)
# for Microchip PHY protocol, timeout on receipt waiting for master
ATCA_RX_TIMEOUT = const(0xEB)
# Device did not respond too many times during a transmission. Could indicate no device present.
ATCA_TOO_MANY_COMM_RETRIES = const(0xEC)
# Supplied buffer is too small for data required
ATCA_SMALL_BUFFER = const(0xED)
# Communication with device failed. Same as in hardware dependent modules.
ATCA_COMM_FAIL = const(0xF0)
# Timed out while waiting for response. Number of bytes received is 0.
ATCA_TIMEOUT = const(0xF1)
# opcode is not supported by the device
ATCA_BAD_OPCODE = const(0xF2)
# received proper wake token
ATCA_WAKE_SUCCESS = const(0xF3)
# chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
ATCA_EXECUTION_ERROR = const(0xF4)
# Function or some element of it hasn't been implemented yet
ATCA_UNIMPLEMENTED = const(0xF5)
# Code failed run-time consistency check
ATCA_ASSERT_FAILURE = const(0xF6)
# Failed to write
ATCA_TX_FAIL = const(0xF7)
# required zone was not locked
ATCA_NOT_LOCKED = const(0xF8)
# For protocols that support device discovery (kit protocol), no devices were found
ATCA_NO_DEVICES = const(0xF9)
# random number generator health test error
ATCA_HEALTH_TEST_ERROR = const(0xFA)
# Couldn't allocate required memory
ATCA_ALLOC_FAILURE = const(0xFB)


def decode_error(error):
    return {
        0x00: (ATCA_SUCCESS, None),
        0x01: (ATCA_CHECKMAC_VERIFY_FAILED, ATCA_EXECUTIONS.CheckmacVerifyFailedError),
        0x03: (ATCA_PARSE_ERROR, ATCA_EXECUTIONS.ParseError),
        0x05: (ATCA_STATUS_ECC, ATCA_EXECUTIONS.EccFaultError),
        0x07: (ATCA_STATUS_SELFTEST_ERROR, ATCA_EXECUTIONS.SelfTestError),
        0x08: (ATCA_HEALTH_TEST_ERROR, ATCA_EXECUTIONS.HealthTestError),
        0x0F: (ATCA_EXECUTION_ERROR, ATCA_EXECUTIONS.ExecutionError),
        0x11: (ATCA_WAKE_SUCCESS, None),
        0xFF: (ATCA_STATUS_CRC, ATCA_EXECUTIONS.CrcError),
    }.get(error, (ATCA_GEN_FAIL, ATCA_EXECUTIONS.GenericError))
