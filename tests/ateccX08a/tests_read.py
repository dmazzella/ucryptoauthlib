# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

log = logging.getLogger("ateccX08a.tests_read")


def run(device=None):
    if not device:
        raise ValueError("device")

    packet = device.atcab_read_serial_number()
    sn0_1, sn8 = packet.response_data[1:1+2], packet.response_data[9+4:9+4+1]
    assert b'\x01#' == sn0_1, bytes(sn0_1)
    assert b'\xee' == sn8, bytes(sn8)
    log.debug("atcab_read_serial_number: %s", hexlify(packet.response_data))
