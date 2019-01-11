# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify


log = logging.getLogger("ateccX08a.tests_random")


def run(device=None):
    if not device:
        raise ValueError("device")

    packet = device.atcab_random()
    log.debug("atcab_random: %s", hexlify(packet.response_data))
