# -*- coding: utf-8 -*-
import logging

from cryptoauthlib.constant import (
    SHA_MODE_SHA256_START,
    SHA_MODE_SHA256_UPDATE,
    SHA_MODE_SHA256_END,
    ATCA_SHA256_BLOCK_SIZE
)
from cryptoauthlib.device import ATECC508A

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("atecc508a.tests_info")


def run(atecc508a=None):
    if not atecc508a:
        atecc508a = ATECC508A()

    message = b'\xBC' * ATCA_SHA256_BLOCK_SIZE
    packet = atecc508a.atcab_sha(message)
    log.info("atcab_sha: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_START)
    log.info("atcab_sha_base - start: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    log.info("atcab_sha_base - update: %s", packet)

    packet = atecc508a.atcab_sha_base(SHA_MODE_SHA256_END)
    log.info("atcab_sha_base - end: %s", packet)
