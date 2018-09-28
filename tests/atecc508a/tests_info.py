# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import INFO_MODE_REVISION, INFO_MODE_STATE
from cryptoauthlib.device import ATECC508A

log = logging.getLogger("atecc508a.tests_info")


def run(atecc508a=None):
    if not atecc508a:
        atecc508a = ATECC508A()

    expected = b'\x07\x00\x00P\x00\x03\x91'
    packet = atecc508a.atcab_info()
    assert expected == packet.response_data
    log.debug("atcab_info: %s", hexlify(packet.response_data))

    packet = atecc508a.atcab_info_base(INFO_MODE_REVISION)
    assert expected == packet.response_data
    log.debug("atcab_info_base - revision: %s", hexlify(packet.response_data))

    expected = b'\x07\x00\x00\x00\x00\x03\xad'
    packet = atecc508a.atcab_info_base(INFO_MODE_STATE)
    assert expected == packet.response_data
    log.debug("atcab_info_base - state: %s", hexlify(packet.response_data))
