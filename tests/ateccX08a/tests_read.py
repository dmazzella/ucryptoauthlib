# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import (
    ATCA_ZONE_CONFIG,
    ATCA_ECC_CONFIG_SIZE,
    LOCK_ZONE_CONFIG,
    LOCK_ZONE_DATA
)

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
    config = b''.join([bytes(packet.response_data[1:-2]) for packet in packets])
    log.debug("atcab_read_config_zone %d: %s", len(config), hexlify(config))

    for slot in range(16):
        packet = device.atcab_is_slot_locked(slot)
        slot_locked = (packet.response_data[0+1]) | ((packet.response_data[1+1]) << 8)
        locked = bool((slot_locked & (1 << slot)) == 0)
        log.debug("atcab_is_slot_locked %d: %r %s", slot, locked, hexlify(packet.response_data))

    for zone in (LOCK_ZONE_CONFIG, LOCK_ZONE_DATA):
        packet = device.atcab_is_locked(zone)
        locked = False
        if zone == LOCK_ZONE_CONFIG:
            zone_str = "LOCK_ZONE_CONFIG"
            locked = bool(packet.response_data[3+1] != 0x55)
        elif zone == LOCK_ZONE_DATA:
            zone_str = "LOCK_ZONE_DATA"
            locked = bool(packet.response_data[2+1] != 0x55)
        log.debug("atcab_is_locked: %s %r %s", zone_str, locked, hexlify(packet.response_data))