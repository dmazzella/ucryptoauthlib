# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging

from cryptoauthlib import constant as ATCA_CONSTANTS

log = logging.getLogger("ateccX08a.tests_selftest")


def run(device=None):
    if not device:
        raise ValueError("device")

    tests = (
        (ATCA_CONSTANTS.SELFTEST_MODE_RNG, "RNG"),
        (ATCA_CONSTANTS.SELFTEST_MODE_ECDSA_SIGN_VERIFY, "ECDSA_SIGN_VERIFY"),
        (ATCA_CONSTANTS.SELFTEST_MODE_ECDH, "ECDH"),
        (ATCA_CONSTANTS.SELFTEST_MODE_AES, "AES"),
        (ATCA_CONSTANTS.SELFTEST_MODE_SHA, "SHA"),
        (ATCA_CONSTANTS.SELFTEST_MODE_ALL, "ALL")
    )
    for mode, mode_str in tests:
        status = device.atcab_selftest(mode)
        assert status
        log.debug("atcab_selftest %s: %s", mode_str, status)
