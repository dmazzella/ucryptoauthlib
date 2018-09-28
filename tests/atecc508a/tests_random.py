# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.device import ATECC508A

log = logging.getLogger("atecc508a.tests_random")


def run(atecc508a=None):
    if not atecc508a:
        atecc508a = ATECC508A()

    packet = atecc508a.atcab_random()
    log.debug("atcab_random: %s", hexlify(packet.response_data))
