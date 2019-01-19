# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify

log = logging.getLogger("ateccX08a.tests_sign")

_MESSAGE = b'a message to sign via ECDSA     '

def run(device=None):
    if not device:
        raise ValueError("device")

    slot = 2
    public_key = device.atcab_get_pubkey(slot)[1:-2]
    log.debug("atcab_get_pubkey %r", hexlify(public_key))
    digest = device.atcab_sha(_MESSAGE)[1:-2]
    log.debug("atcab_sha %r %r", _MESSAGE, hexlify(digest))
    signature = device.atcab_sign(slot, digest)[1:-2]
    log.debug("atcab_sign %r", hexlify(signature))
    verified = device.atcab_verify_extern(digest, signature, public_key)
    log.debug("atcab_verify_extern %r", verified)
