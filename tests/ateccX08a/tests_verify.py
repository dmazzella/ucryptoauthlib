# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging
from ubinascii import hexlify, unhexlify

log = logging.getLogger("ateccX08a.tests_verify")


def run(device=None, configuration=None):
    if not device:
        raise ValueError("device")

    private_key =  unhexlify("f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664")
    public_key = unhexlify("048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101")
    