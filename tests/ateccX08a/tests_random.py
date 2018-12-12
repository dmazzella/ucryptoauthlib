# -*- coding: utf-8 -*-
import logging
from binascii import hexlify


log = logging.getLogger("ateccX08a.tests_random")


def run(device=None):
    if not device:
        raise ValueError("device")

    packet = device.atcab_random()
    log.debug("atcab_random: %s", hexlify(packet.response_data))
