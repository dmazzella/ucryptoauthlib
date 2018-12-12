# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import (
    SHA_MODE_SHA256_START,
    SHA_MODE_SHA256_UPDATE,
    SHA_MODE_SHA256_END,
    ATCA_SHA256_BLOCK_SIZE
)

log = logging.getLogger("ateccX08a.tests_sha")


def run(device=None):
    if not device:
        raise ValueError("device")

    message = b'\xBC' * ATCA_SHA256_BLOCK_SIZE
    packet = device.atcab_sha(message)
    log.debug("atcab_sha: %s", hexlify(packet.response_data))

    message = b'\x5A' * ATCA_SHA256_BLOCK_SIZE
    packet = device.atcab_sha_base(SHA_MODE_SHA256_START)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_END)
    log.debug("atcab_sha_base: %s", hexlify(packet.response_data))

    # test HW SHA with a long message > SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * (ATCA_SHA256_BLOCK_SIZE + 63)
    packet = device.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test HW SHA with a short message < SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * 10
    packet = device.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test NIST HW SHA
    message = "abc"
    packet = device.atcab_sha(message)
    log.debug("atcab_sha nist 1: %s", hexlify(packet.response_data))

    message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    packet = device.atcab_sha(message)
    log.debug("atcab_sha nist 2: %s", hexlify(packet.response_data))
