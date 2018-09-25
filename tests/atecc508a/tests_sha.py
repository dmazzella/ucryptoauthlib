# -*- coding: utf-8 -*-
import logging

from cryptoauthlib.constant import (
    SHA_MODE_SHA256_START,
    SHA_MODE_SHA256_UPDATE,
    SHA_MODE_SHA256_END,
    ATCA_SHA256_BLOCK_SIZE
)
from cryptoauthlib.device import ATECC508A

log = logging.getLogger("atecc508a.tests_info")


def run(atecc508a=None):
    if not atecc508a:
        atecc508a = ATECC508A()

    message = b'\xBC' * ATCA_SHA256_BLOCK_SIZE
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha: %s", packet)

    message = b'\x5A' * ATCA_SHA256_BLOCK_SIZE
    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_START)
    log.debug("atcab_sha_base - start: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    log.debug("atcab_sha_base - update: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    log.debug("atcab_sha_base - update: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    log.debug("atcab_sha_base - update: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_END)
    log.debug("atcab_sha_base - end: %s", packet)

    ## test HW SHA with a long message > SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * (ATCA_SHA256_BLOCK_SIZE + 63)
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), packet)

    ## test HW SHA with a short message < SHA block size and not an exact SHA block-size increment
    message = b'\xBC' * 10
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha %d: %s", len(message), packet)

    ## test NIST HW SHA
    message = "abc"
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha nist 1: %s", packet)

    message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    packet = atecc508a.atcab_sha(message)
    log.debug("atcab_sha nist 2: %s", packet)
