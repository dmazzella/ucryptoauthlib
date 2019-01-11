# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify

from cryptoauthlib.constant import (
    NONCE_MODE_SEED_UPDATE,
    NONCE_MODE_NO_SEED_UPDATE,
    NONCE_MODE_PASSTHROUGH,
    NONCE_MODE_TARGET_TEMPKEY,
    NONCE_MODE_TARGET_MSGDIGBUF,
    NONCE_MODE_TARGET_ALTKEYBUF,
)

log = logging.getLogger("ateccX08a.tests_nonce")


def run(device=None):
    if not device:
        raise ValueError("device")

    numbers = b'\x00' * 32

    packet = device.atcab_nonce_base(NONCE_MODE_SEED_UPDATE, numbers=numbers)
    log.debug("atcab_nonce_base NONCE_MODE_SEED_UPDATE: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_base(NONCE_MODE_NO_SEED_UPDATE, numbers=numbers)
    log.debug("atcab_nonce_base NONCE_MODE_NO_SEED_UPDATE: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_base(NONCE_MODE_PASSTHROUGH, numbers=numbers)
    log.debug("atcab_nonce_base NONCE_MODE_PASSTHROUGH: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce(numbers=numbers)
    log.debug("atcab_nonce: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, numbers=numbers)
    log.debug("atcab_nonce_load NONCE_MODE_TARGET_TEMPKEY: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_load(NONCE_MODE_TARGET_MSGDIGBUF, numbers=numbers)
    log.debug("atcab_nonce_load NONCE_MODE_TARGET_MSGDIGBUF: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_load(NONCE_MODE_TARGET_ALTKEYBUF, numbers=numbers)
    log.debug("atcab_nonce_load NONCE_MODE_TARGET_ALTKEYBUF: %s", hexlify(packet.response_data))

    packet = device.atcab_nonce_rand(numbers=numbers)
    log.debug("atcab_nonce_rand: %s", hexlify(packet.response_data))

    packet = device.atcab_challenge(numbers=numbers)
    log.debug("atcab_challenge: %s", hexlify(packet.response_data))

    packet = device.atcab_challenge_seed_update(numbers=numbers)
    log.debug("atcab_challenge_seed_update: %s", hexlify(packet.response_data))
