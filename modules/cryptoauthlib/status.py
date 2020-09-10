# -*- coding: utf-8 -*-
# pylint: disable=E0401
import sys
from micropython import const

from cryptoauthlib import exceptions as ATCA_EXECUTIONS


class S(object):

    def __getattr__(self, a):
        if a == "ATCA_SUCCESS":
            return const(0x00)
        elif a == "ATCA_CONFIG_ZONE_LOCKED":
            return const(0x01)
        elif a == "ATCA_DATA_ZONE_LOCKED":
            return const(0x02)
        elif a == "ATCA_WAKE_FAILED":
            return const(0xD0)
        elif a == "ATCA_CHECKMAC_VERIFY_FAILED":
            return const(0xD1)
        elif a == "ATCA_PARSE_ERROR":
            return const(0xD2)
        elif a == "ATCA_STATUS_CRC":
            return const(0xD4)
        elif a == "ATCA_STATUS_UNKNOWN":
            return const(0xD5)
        elif a == "ATCA_STATUS_ECC":
            return const(0xD6)
        elif a == "ATCA_STATUS_SELFTEST_ERROR":
            return const(0xD7)
        elif a == "ATCA_FUNC_FAIL":
            return const(0xE0)
        elif a == "ATCA_GEN_FAIL":
            return const(0xE1)
        elif a == "ATCA_BAD_PARAM":
            return const(0xE2)
        elif a == "ATCA_INVALID_ID":
            return const(0xE3)
        elif a == "ATCA_INVALID_SIZE":
            return const(0xE4)
        elif a == "ATCA_RX_CRC_ERROR":
            return const(0xE5)
        elif a == "ATCA_RX_FAIL":
            return const(0xE6)
        elif a == "ATCA_RX_NO_RESPONSE":
            return const(0xE7)
        elif a == "ATCA_RESYNC_WITH_WAKEUP":
            return const(0xE8)
        elif a == "ATCA_PARITY_ERROR":
            return const(0xE9)
        elif a == "ATCA_TX_TIMEOUT":
            return const(0xEA)
        elif a == "ATCA_RX_TIMEOUT":
            return const(0xEB)
        elif a == "ATCA_TOO_MANY_COMM_RETRIES":
            return const(0xEC)
        elif a == "ATCA_SMALL_BUFFER":
            return const(0xED)
        elif a == "ATCA_COMM_FAIL":
            return const(0xF0)
        elif a == "ATCA_TIMEOUT":
            return const(0xF1)
        elif a == "ATCA_BAD_OPCODE":
            return const(0xF2)
        elif a == "ATCA_WAKE_SUCCESS":
            return const(0xF3)
        elif a == "ATCA_EXECUTION_ERROR":
            return const(0xF4)
        elif a == "ATCA_UNIMPLEMENTED":
            return const(0xF5)
        elif a == "ATCA_ASSERT_FAILURE":
            return const(0xF6)
        elif a == "ATCA_TX_FAIL":
            return const(0xF7)
        elif a == "ATCA_NOT_LOCKED":
            return const(0xF8)
        elif a == "ATCA_NO_DEVICES":
            return const(0xF9)
        elif a == "ATCA_HEALTH_TEST_ERROR":
            return const(0xFA)
        elif a == "ATCA_ALLOC_FAILURE":
            return const(0xFB)
        elif a == "ATCA_WATCHDOG_ABOUT_TO_EXPIRE":
            return const(0xEE)

    def decode_error(self, error):
        return {
            0x00: (self.ATCA_SUCCESS, None),
            0x01: (self.ATCA_CHECKMAC_VERIFY_FAILED, ATCA_EXECUTIONS.CheckmacVerifyFailedError),
            0x03: (self.ATCA_PARSE_ERROR, ATCA_EXECUTIONS.ParseError),
            0x05: (self.ATCA_STATUS_ECC, ATCA_EXECUTIONS.EccFaultError),
            0x07: (self.ATCA_STATUS_SELFTEST_ERROR, ATCA_EXECUTIONS.SelfTestError),
            0x08: (self.ATCA_HEALTH_TEST_ERROR, ATCA_EXECUTIONS.HealthTestError),
            0x0F: (self.ATCA_EXECUTION_ERROR, ATCA_EXECUTIONS.ExecutionError),
            0x11: (self.ATCA_WAKE_SUCCESS, None),
            0xEE: (self.ATCA_WATCHDOG_ABOUT_TO_EXPIRE, ATCA_EXECUTIONS.WatchDogAboutToExpireError),
            0xFF: (self.ATCA_STATUS_CRC, ATCA_EXECUTIONS.CrcError),
        }.get(error, (self.ATCA_GEN_FAIL, ATCA_EXECUTIONS.GenericError))


sys.modules[__name__] = S()
