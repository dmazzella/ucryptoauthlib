# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

log = logging.getLogger("ateccX08a.tests_write")


def run(device=None):
    if not device:
        raise ValueError("device")
