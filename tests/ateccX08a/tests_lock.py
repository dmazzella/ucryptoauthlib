# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify

log = logging.getLogger("ateccX08a.tests_lock")


def run(device=None):
    if not device:
        raise ValueError("device")
