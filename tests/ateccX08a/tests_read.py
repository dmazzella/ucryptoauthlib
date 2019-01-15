# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify
from uio import BytesIO, StringIO

from cryptoauthlib import constant as ATCA_CONSTANTS
from cryptoauthlib import util as ATEC_UTIL

log = logging.getLogger("ateccX08a.tests_read")

def run(device=None):
    if not device:
        raise ValueError("device")

    packet = device.atcab_read_serial_number()
    sn0_1, sn8 = packet.response_data[1:1+2], packet.response_data[9+4:9+4+1]
    assert b'\x01#' == sn0_1, hexlify(sn0_1)
    assert b'\xee' == sn8, hexlify(sn8)
    log.debug("atcab_read_serial_number: %s", hexlify(packet.response_data))

    packets = device.atcab_read_config_zone()
    config = b''.join([bytes(packet.response_data[1:-2])
                       for packet in packets])
    log.debug("atcab_read_config_zone %d: %s", len(config), hexlify(config))
    # ATEC_UTIL.dump_configuration(config)

    for slot in range(16):
        slot_locked = device.atcab_is_slot_locked(slot)
        log.debug("atcab_is_slot_locked %d: %s", slot, slot_locked)

    locked_config = device.atcab_is_locked(ATCA_CONSTANTS.LOCK_ZONE_CONFIG)
    log.debug("atcab_is_locked LOCK_ZONE_CONFIG: %r", locked_config)

    locked_data = device.atcab_is_locked(ATCA_CONSTANTS.LOCK_ZONE_DATA)
    log.debug("atcab_is_locked LOCK_ZONE_DATA: %r", locked_data)

    slot = 12
    public_key = device.atcab_read_pubkey(slot)
    log.debug("atcab_read_pubkey slot %d: %s", slot, hexlify(public_key))
