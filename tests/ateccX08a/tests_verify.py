# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify, unhexlify

from cryptoauthlib import constant as ATCA_CONSTANTS

log = logging.getLogger("ateccX08a.tests_verify")

_TEST_KEYS = {
    "PRIVATE": bytes([
        0XF3, 0XFC, 0XCC, 0X0D, 0X00, 0XD8, 0X03, 0X19, 0X54, 0XF9, 0X08, 0X64, 0XD4, 0X3C, 0X24, 0X7F,
        0X4B, 0XF5, 0XF0, 0X66, 0X5C, 0X6B, 0X50, 0XCC, 0X17, 0X74, 0X9A, 0X27, 0XD1, 0XCF, 0X76, 0X64
    ]),
    "PUBLIC": bytes([
        0X8D, 0X61, 0X7E, 0X65, 0XC9, 0X50, 0X8E, 0X64, 0XBC, 0XC5, 0X67, 0X3A, 0XC8, 0X2A, 0X67, 0X99,
        0XDA, 0X3C, 0X14, 0X46, 0X68, 0X2C, 0X25, 0X8C, 0X46, 0X3F, 0XFF, 0XDF, 0X58, 0XDF, 0XD2, 0XFA,
        0X3E, 0X6C, 0X37, 0X8B, 0X53, 0XD7, 0X95, 0XC4, 0XA4, 0XDF, 0XFB, 0X41, 0X99, 0XED, 0XD7, 0X86,
        0X2F, 0X23, 0XAB, 0XAF, 0X02, 0X03, 0XB4, 0XB8, 0X91, 0X1B, 0XA0, 0X56, 0X99, 0X94, 0XE1, 0X01
    ]),
    "MESSAGE": b'a message to sign via ECDSA     ',
    "SIGNATURE": {
        "R": bytes([
            0X71, 0X07, 0X7D, 0X35, 0X6F, 0XCD, 0X70, 0XD4, 0XCC, 0X47, 0X2A, 0XD0, 0X49, 0X0E, 0X75, 0XAB,
            0XC5, 0X41, 0X98, 0XEE, 0X6A, 0X96, 0X7B, 0X90, 0XF2, 0XC7, 0XE3, 0XC8, 0X2B, 0XBF, 0X54, 0X96
        ]),
        "S": bytes([
            0X77, 0X8E, 0XFE, 0X0B, 0XF6, 0X9D, 0X15, 0XED, 0XA0, 0X71, 0XBD, 0XD3, 0XFE, 0X46, 0X99, 0X26,
            0X31, 0XF8, 0X80, 0X01, 0X13, 0X76, 0XCD, 0X45, 0X7C, 0X62, 0X55, 0X43, 0XC9, 0X7F, 0XCC, 0XD9
        ])
    }
}


def run(device=None, configuration=None):
    if not device:
        raise ValueError("device")

    public_key = _TEST_KEYS["PUBLIC"]
    message = _TEST_KEYS["MESSAGE"]
    digest = device.atcab_sha(message)[1:-2]
    signature = _TEST_KEYS["SIGNATURE"]["R"] + _TEST_KEYS["SIGNATURE"]["S"]
    # # verify the signature extern
    verified = device.atcab_verify_extern(digest, signature, public_key)
    log.info("atcab_verify_extern %r", verified)

    # # verify the signature stored
    # slot = 11
    # device.atcab_nonce_load(ATCA_CONSTANTS.NONCE_MODE_TARGET_TEMPKEY, digest)
    # verified = device.atcab_verify_stored(message, signature, slot)
    # log.info("atcab_verify_stored %r", verified)
