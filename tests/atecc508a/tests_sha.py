# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import (
    SHA_MODE_SHA256_START,
    SHA_MODE_SHA256_UPDATE,
    SHA_MODE_SHA256_END,
    ATCA_SHA256_BLOCK_SIZE
)
from cryptoauthlib.device import ATECC508A

log = logging.getLogger("atecc508a.tests_sha")


def run(atecc508a=None):
    if not atecc508a:
        atecc508a = ATECC508A()

    message = b'\xBC' * ATCA_SHA256_BLOCK_SIZE
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha: %s", hexlify(packet.response_data))

    message = b'\x5A' * ATCA_SHA256_BLOCK_SIZE
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_START)
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_END)
    log.debug("atcab_sha_base: %s", hexlify(packet.response_data))

    # test HW SHA with a long message > SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * (ATCA_SHA256_BLOCK_SIZE + 63)
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test HW SHA with a short message < SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * 10
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test NIST HW SHA
    message = "abc"
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha nist 1: %s", hexlify(packet.response_data))

    message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha nist 2: %s", hexlify(packet.response_data))
