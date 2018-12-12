# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import INFO_MODE_REVISION, INFO_MODE_STATE

log = logging.getLogger("ateccX08a.tests_info")


def run(device=None):
    if not device:
        raise ValueError("device")

    expected = (
        b'\x07\x00\x00P\x00\x03\x91', # ATECC508A
        b'\x07\x00\x00`\x02\x808' # ATECC608A
    )
    packet = device.atcab_info()
    assert packet.response_data in expected, packet.response_data
    log.debug("atcab_info: %s", hexlify(packet.response_data))

    packet = device.atcab_info_base(INFO_MODE_REVISION)
    assert packet.response_data in expected, packet.response_data
    log.debug("atcab_info_base - revision: %s", hexlify(packet.response_data))

    expected = b'\x07\x00\x00\x00\x00\x03\xad'
    packet = device.atcab_info_base(INFO_MODE_STATE)
    assert expected == packet.response_data, packet.response_data
    log.debug("atcab_info_base - state: %s", hexlify(packet.response_data))
